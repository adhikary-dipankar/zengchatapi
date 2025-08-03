using Microsoft.AspNetCore.Mvc;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using BCrypt.Net;
using ZenGChatApi.Services;
using ZenGChatApi.Models;
using System.Threading.Tasks;
using System.Net.Http;
using System.Text.Json;
using System.Net.Mail;
using System.Net;

namespace ZenGChatApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly MongoDbService _mongoDbService;
        private readonly string _jwtSecret;
        private readonly IConfiguration _configuration;
        private readonly HttpClient _httpClient;

        public AuthController(MongoDbService mongoDbService, IConfiguration configuration, IHttpClientFactory httpClientFactory)
        {
            _mongoDbService = mongoDbService;
            _jwtSecret = configuration["Jwt:Secret"] ?? Environment.GetEnvironmentVariable("Jwt__Secret") ?? throw new InvalidOperationException("JWT Secret is not configured");
            _configuration = configuration;
            _httpClient = httpClientFactory.CreateClient();
        }

        [HttpPost("signup")]
        public async Task<IActionResult> Signup([FromBody] SignupModel model)
        {
            var existingUser = await _mongoDbService.GetUserByEmailAsync(model.Email);
            if (existingUser != null)
            {
                return BadRequest("Email already exists.");
            }

            var user = new User
            {
                Email = model.Email,
                Username = model.Username,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(model.Password),
                Bio = model.Bio
            };

            await _mongoDbService.CreateUserAsync(user);
            return Ok();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _mongoDbService.GetUserByEmailAsync(model.Email);
            if (user == null || !BCrypt.Net.BCrypt.Verify(model.Password, user.PasswordHash))
            {
                return Unauthorized("Invalid credentials.");
            }

            var token = GenerateJwtToken(user);
            return Ok(new { Token = token, UserId = user.Id, Username = user.Username, Bio = user.Bio });
        }

        [HttpPost("google-login")]
        public async Task<IActionResult> GoogleLogin([FromBody] GoogleLoginModel model)
        {
            var payload = await ValidateGoogleToken(model.Token);
            if (payload == null)
            {
                return Unauthorized("Invalid Google token.");
            }

            var email = payload["email"]?.ToString();
            var name = payload["name"]?.ToString();
            if (string.IsNullOrEmpty(email))
            {
                return BadRequest("Email not found in Google token.");
            }

            var user = await _mongoDbService.GetUserByEmailAsync(email);
            if (user == null)
            {
                user = new User
                {
                    Email = email,
                    Username = name ?? email.Split('@')[0],
                    PasswordHash = "", // No password for Google users
                    Bio = ""
                };
                await _mongoDbService.CreateUserAsync(user);
            }

            var token = GenerateJwtToken(user);
            return Ok(new { Token = token, UserId = user.Id, Username = user.Username, Bio = user.Bio });
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel model)
        {
            var user = await _mongoDbService.GetUserByEmailAsync(model.Email);
            if (user == null)
            {
                return Ok(); // Don't reveal if email exists
            }

            var resetToken = Guid.NewGuid().ToString();
            var expires = DateTime.UtcNow.AddHours(1);
            await _mongoDbService.SaveResetTokenAsync(user.Id, resetToken, expires);

            var resetLink = $"{_configuration["Frontend:BaseUrl"]}/reset-password?token={resetToken}&email={Uri.EscapeDataString(model.Email)}";
            await SendResetEmail(model.Email, resetLink);

            return Ok();
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordModel model)
        {
            var user = await _mongoDbService.GetUserByEmailAsync(model.Email);
            if (user == null)
            {
                return BadRequest("Invalid email or token.");
            }

            var isValidToken = await _mongoDbService.ValidateResetTokenAsync(user.Id, model.Token);
            if (!isValidToken)
            {
                return BadRequest("Invalid or expired token.");
            }

            await _mongoDbService.UpdateUserPasswordAsync(user.Id, BCrypt.Net.BCrypt.HashPassword(model.NewPassword));
            await _mongoDbService.DeleteResetTokenAsync(user.Id);

            return Ok();
        }

        [HttpGet("users")]
        public async Task<IActionResult> GetUsers()
        {
            var users = await _mongoDbService.GetAllUsersAsync();
            return Ok(users.Select(u => new { u.Id, u.Username, u.Bio }));
        }

        [HttpPut("profile")]
        public async Task<IActionResult> UpdateProfile([FromBody] ProfileModel model)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
            {
                return Unauthorized();
            }

            await _mongoDbService.UpdateUserAsync(userId, model.Username, model.Bio);
            return Ok();
        }

        private string GenerateJwtToken(User user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_jwtSecret);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.Id),
                    new Claim(ClaimTypes.Name, user.Username)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                Issuer = "ZenGChatApi",
                Audience = "ZenGChatFrontend",
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private async Task<Dictionary<string, object>?> ValidateGoogleToken(string idToken)
        {
            try
            {
                var response = await _httpClient.GetAsync($"https://oauth2.googleapis.com/tokeninfo?id_token={idToken}");
                if (!response.IsSuccessStatusCode)
                {
                    return null;
                }
                var content = await response.Content.ReadAsStringAsync();
                return JsonSerializer.Deserialize<Dictionary<string, object>>(content);
            }
            catch
            {
                return null;
            }
        }

        private async Task SendResetEmail(string email, string resetLink)
        {
            var smtpHost = _configuration["Smtp:Host"] ?? "smtp.gmail.com";
            var smtpPort = int.Parse(_configuration["Smtp:Port"] ?? "587");
            var smtpUser = _configuration["Smtp:Username"] ?? Environment.GetEnvironmentVariable("Smtp__Username");
            var smtpPass = _configuration["Smtp:Password"] ?? Environment.GetEnvironmentVariable("Smtp__Password");

            using var client = new SmtpClient(smtpHost, smtpPort)
            {
                EnableSsl = true,
                Credentials = new NetworkCredential(smtpUser, smtpPass)
            };

            var mail = new MailMessage
            {
                From = new MailAddress(smtpUser, "Zen G Chat"),
                Subject = "Password Reset Request",
                Body = $"Click the link to reset your password: <a href='{resetLink}'>Reset Password</a>",
                IsBodyHtml = true
            };
            mail.To.Add(email);

            await client.SendMailAsync(mail);
        }
    }

    public class GoogleLoginModel
    {
        public string Token { get; set; } = string.Empty;
    }

    public class ForgotPasswordModel
    {
        public string Email { get; set; } = string.Empty;
    }

    public class ResetPasswordModel
    {
        public string Email { get; set; } = string.Empty;
        public string Token { get; set; } = string.Empty;
        public string NewPassword { get; set; } = string.Empty;
    }
}
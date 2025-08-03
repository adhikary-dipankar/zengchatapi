namespace ZenGChatApi.Models;

public class SignupModel
{
    public string Email { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Bio { get; set; } = string.Empty;
}

public class LoginModel
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class ProfileModel
{
    public string Username { get; set; } = string.Empty;
    public string Bio { get; set; } = string.Empty;
}
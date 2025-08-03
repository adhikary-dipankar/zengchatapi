using Microsoft.AspNetCore.Mvc;
using ZenGChatApi.Services;
using ZenGChatApi.Models;
using Microsoft.AspNetCore.Authorization;

namespace ZenGChatApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class ChatController : ControllerBase
    {
        private readonly MongoDbService _mongoDbService;

        public ChatController(MongoDbService mongoDbService)
        {
            _mongoDbService = mongoDbService;
        }

        [HttpGet("messages/{receiverId}")]
        public async Task<IActionResult> GetMessages(string receiverId)
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
            {
                return Unauthorized();
            }

            var messages = await _mongoDbService.GetMessagesAsync(userId, receiverId);
            return Ok(messages);
        }

        [HttpPost("messages")]
        public async Task<IActionResult> SendMessage([FromBody] Message model)
        {
            var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userId == null)
            {
                return Unauthorized();
            }

            var message = new Message
            {
                SenderId = userId,
                ReceiverId = model.ReceiverId,
                Content = model.Content,
                Timestamp = DateTime.UtcNow
            };

            await _mongoDbService.CreateMessageAsync(message);
            return Ok();
        }
    }
}
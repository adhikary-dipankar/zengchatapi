using MongoDB.Bson;

namespace ZenGChatApi.Models;

public class Message
{
    public string Id { get; set; } = ObjectId.GenerateNewId().ToString();
    public string SenderId { get; set; } = string.Empty;
    public string ReceiverId { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public DateTime Timestamp { get; set; }
}
using MongoDB.Driver;
using ZenGChatApi.Models;

namespace ZenGChatApi.Services;

public class MongoDbService
{
    private readonly IMongoCollection<User> _users;
    private readonly IMongoCollection<Message> _messages;
    private readonly IMongoCollection<PasswordResetToken> _resetTokens;

    public MongoDbService(IMongoClient client, string databaseName)
    {
        var database = client.GetDatabase(databaseName);
        _users = database.GetCollection<User>("Users");
        _messages = database.GetCollection<Message>("Messages");
        _resetTokens = database.GetCollection<PasswordResetToken>("PasswordResetTokens");
    }

    public async Task<User?> GetUserByEmailAsync(string email) =>
        await _users.Find(u => u.Email == email).FirstOrDefaultAsync();

    public async Task<User?> GetUserByIdAsync(string id) =>
        await _users.Find(u => u.Id == id).FirstOrDefaultAsync();

    public async Task<List<User>> GetAllUsersAsync() =>
        await _users.Find(_ => true).ToListAsync();

    public async Task CreateUserAsync(User user) =>
        await _users.InsertOneAsync(user);

    public async Task UpdateUserAsync(string id, string username, string bio) =>
        await _users.UpdateOneAsync(
            u => u.Id == id,
            Builders<User>.Update.Set(u => u.Username, username).Set(u => u.Bio, bio));

    public async Task UpdateUserPasswordAsync(string id, string passwordHash) =>
        await _users.UpdateOneAsync(
            u => u.Id == id,
            Builders<User>.Update.Set(u => u.PasswordHash, passwordHash));

    public async Task SaveResetTokenAsync(string userId, string token, DateTime expires) =>
        await _resetTokens.InsertOneAsync(new PasswordResetToken
        {
            UserId = userId,
            Token = token,
            Expires = expires
        });

    public async Task<bool> ValidateResetTokenAsync(string userId, string token) =>
        await _resetTokens.Find(t => t.UserId == userId && t.Token == token && t.Expires > DateTime.UtcNow)
                          .AnyAsync();

    public async Task DeleteResetTokenAsync(string userId) =>
        await _resetTokens.DeleteManyAsync(t => t.UserId == userId);

    public async Task<List<Message>> GetMessagesAsync(string userId, string receiverId) =>
        await _messages.Find(m => (m.SenderId == userId && m.ReceiverId == receiverId) || 
                                  (m.SenderId == receiverId && m.ReceiverId == userId))
                      .SortBy(m => m.Timestamp)
                      .ToListAsync();

    public async Task CreateMessageAsync(Message message) =>
        await _messages.InsertOneAsync(message);
}

public class PasswordResetToken
{
    public string Id { get; set; } = MongoDB.Bson.ObjectId.GenerateNewId().ToString();
    public string UserId { get; set; } = string.Empty;
    public string Token { get; set; } = string.Empty;
    public DateTime Expires { get; set; }
}


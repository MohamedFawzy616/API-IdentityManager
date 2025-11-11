using IdentityManager.Data.Repository;
using IdentityManager.Models;
using Microsoft.EntityFrameworkCore;

namespace IdentityManager.Data
{
    public class RefreshTokenRepository : IRefreshTokenRepository
    {
        private readonly ApplicationDbContext context;

        public RefreshTokenRepository(ApplicationDbContext _context)
        {
            context = _context;
        }

        public async Task<RefreshToken> AddAsync(RefreshToken refreshToken)
        {
            await context.AddAsync(refreshToken);
            await context.SaveChangesAsync();
            return refreshToken;
        }

        public async Task<RefreshToken> UpdateAsync(RefreshToken refreshToken)
        {
            context.Update(refreshToken);
            await context.SaveChangesAsync();
            return refreshToken;
        }

        public async Task<List<RefreshToken>> GetAllTokensAsync()
        {
            var refreshTokens = await context.RefreshTokens.ToListAsync();
            return refreshTokens;
        }

        public async Task<RefreshToken> GetByTokenAsync(string token)
        {
            var refreshToken = await context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);
            return refreshToken;
        }

        public async Task<List<RefreshToken>> GetTokensByUserIdAsync(string userId)
        {
            return await context.RefreshTokens.Where(rt => rt.UserId == userId && rt.IsRevoked == false).ToListAsync();
        }

        public async Task<RefreshToken> GetTokenByDeviceIdandUserIdAsync(string userId, string deviceId)
        {
            var result = await context.RefreshTokens.FirstOrDefaultAsync(rt => rt.UserId == userId && rt.DeviceId == deviceId && rt.IsRevoked == false);
            return result;
        }

        public async Task<List<RefreshToken>> GetExpiredTokensAsync()
        {
            return await context.RefreshTokens.Where(rt => !rt.IsRevoked && rt.Expires < DateTime.UtcNow).ToListAsync();
        }

        public async Task<bool> IsTokenRevokedAsync(string token)
        {
            var result = await context.RefreshTokens.FirstOrDefaultAsync(rt => rt.Token == token);

            return result.IsRevoked;
        }

        public async Task<List<RefreshToken>> GetActiveSessions(string userId)
        {
            var activeSessions = await context.RefreshTokens.Where(rt => rt.UserId == userId && !rt.IsRevoked && rt.Expires > DateTime.UtcNow).ToListAsync();
            return activeSessions;
        }
    }
}


/*
 نقدر نقول:

الميثود	مكانها الصحيح	السبب
CreateAsync(string userId)	✅ Repository	إنشاء سجل جديد فقط في DB.
GetByTokenAsync(string token)	✅ Repository	قراءة من DB فقط.
RotateAsync(RefreshToken oldToken)	⚠️ جزئيًا في Service	لأنها تحتاج منطق (إلغاء القديم + إنشاء جديد).
RevokeAsync(string token)	⚠️ جزئيًا في Service	لأنها تحتاج تحقق (هل التوكن صالح؟ هل تم إلغاؤه بالفعل؟).
RenewTokensAsync(string ipAddress)	❌ لا توضع في Repository	لأنها Business Logic بالكامل (تجديد، توليد JWT جديد، تحديث DB).
 */
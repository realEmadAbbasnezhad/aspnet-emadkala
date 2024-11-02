using Aspnet_EmadKala.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Aspnet_EmadKala.Services;

public static partial class BuilderExtensions
{
    public static IdentityBuilder AddOtpTokenProvider(this IdentityBuilder builder)
    {
        return builder.AddTokenProvider(nameof(OtpTokenProvider),
            typeof(OtpTokenProvider));
    }
}

public class OtpTokenProvider(
    DatabaseModel dbContext,
    IPasswordHasher<EmadKalaUser> passwordHasher) :
    TotpSecurityStampBasedTokenProvider<EmadKalaUser>
{
    #region TokenProvider

    private static readonly Random CodeGenerator = new();

    public override Task<bool> CanGenerateTwoFactorTokenAsync
        (UserManager<EmadKalaUser> _0, EmadKalaUser _1)
    {
        return Task.FromResult(false);
    }

    // NEVER call this outside of this class.
    public override async Task<string> GenerateAsync
        (string _0, UserManager<EmadKalaUser> userManager, EmadKalaUser user)
    {
        user = await dbContext.Users.FirstAsync(x => x.Id == user.Id);
        
        // generate code
        var code = "";
        for (var i = 0; i < 6; i++) code += CodeGenerator.Next(0, 9).ToString();

        // save it to database
        user.OtpHash = passwordHasher.HashPassword(user, code);

        await dbContext.SaveChangesAsync();
        return code;
    }

    // NEVER call this outside of this class.
    public override async Task<bool> ValidateAsync
        (string _0, string code, UserManager<EmadKalaUser> userManager, EmadKalaUser user)
    {
        user = await dbContext.Users.FirstAsync(x => x.Id == user.Id);
        
        // check hash
        var result = passwordHasher.VerifyHashedPassword(
            user, user.OtpHash!, code);

        if (result == PasswordVerificationResult.Failed) return false;
        user.OtpHash = null;

        await dbContext.SaveChangesAsync();
        return true;
    }

    #endregion

    #region HighLevel

    // call this instead of 'GenerateUserTokenAsync'. return null means cool down.
    public static async Task<string?> GenerateOtpAsync
        (UserManager<EmadKalaUser> userManager, EmadKalaUser user, DatabaseModel accountDbContext)
    {
        user = await accountDbContext.Users.FirstAsync(x => x.Id == user.Id);
        
        if (user.OtpGenerateCount >= 1)
        {
            if (user.OtpGenerateLastTimeUtc.AddMinutes(5) <= DateTime.UtcNow)
            {
                // account on code cooldown and time has been ended
                user.OtpGenerateCount = 0;
            }
            else
            {
                // account on code cooldown and time has not been ended
                return null;
            }
        }

        user.OtpGenerateCount++;
        user.OtpGenerateLastTimeUtc = DateTime.UtcNow;

        await accountDbContext.SaveChangesAsync();
        return await userManager.GenerateUserTokenAsync(user, nameof(OtpTokenProvider), "");
    }

    public enum VerifyResult
    {
        Success,
        WrongCode,
        NoRequest,
        Expired,
        Cooldown
    }

    // call this instead of 'VerifyUserTokenAsync'.
    public static async Task<VerifyResult> ValidateOtpAsync
    (UserManager<EmadKalaUser> userManager, EmadKalaUser user,
        string code, DatabaseModel accountDbContext)
    {
        user = await accountDbContext.Users.FirstAsync(x => x.Id == user.Id);
        
        if (user.OtpHash == null) return VerifyResult.NoRequest;
        if (user.OtpGenerateLastTimeUtc.AddMinutes(15) <= DateTime.UtcNow) return VerifyResult.Expired;

        if (user.OtpValidateFailCount >= 3)
        {
            if (user.OtpValidateLastTimeUtc.AddMinutes(1) <= DateTime.UtcNow)
            {
                // account on code cooldown and time has been ended
                user.OtpValidateFailCount = 0;
                // no need for 'accountDbContext.SaveChangesAsync()' because its calling anyway.
            }
            else
            {
                // account on code cooldown and time has not been ended
                return VerifyResult.Cooldown;
            }
        }

        if (!await userManager.VerifyUserTokenAsync(user, nameof(OtpTokenProvider), "", code))
        {
            user.OtpValidateFailCount++;
            user.OtpValidateLastTimeUtc = DateTime.UtcNow;

            await accountDbContext.SaveChangesAsync();
            return VerifyResult.WrongCode;
        }

        user.OtpValidateFailCount = 0;
        user.OtpGenerateLastTimeUtc = DateTime.MinValue;
        
        await accountDbContext.SaveChangesAsync();
        return VerifyResult.Success;
    }

    #endregion
}
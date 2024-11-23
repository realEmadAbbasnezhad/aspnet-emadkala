using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Aspnet_EmadKala.Models;
using Aspnet_EmadKala.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ShikMelk.WebApp.Services;

namespace Aspnet_EmadKala.Controllers;

[ApiController, Route("Api/Account"), Authorize]
public class AccountController(
    UserManager<EmadKalaUser> userManager,
    IConfiguration configuration,
    DatabaseModel dbContext,
    ISmsService smsService) : ControllerBase
{
    #region Portal

    public class PortalRequestModel
    {
        [Required, RegularExpression("^(?:0)?(9\\d{9})$")]
        public string PhoneNumber { set; get; } = "";
        public bool? RequestOtp { get; set; } = null;
    }

    public class PortalRespondModel
    {
        public bool? NewUser { get; set; } = null;
        public bool? HasPassword { get; set; } = null;
        public bool? OptCooldown { get; set; } = null;
    }

    [HttpPost("Portal"), AllowAnonymous]
    public async Task<PortalRespondModel> Portal([FromBody] PortalRequestModel request)
    {
        var respond = new PortalRespondModel { NewUser = null, HasPassword = null, OptCooldown = null };
        if (User.Identity is { IsAuthenticated: true }) return respond;
        var claimedUser = new EmadKalaUser
        {
            PhoneNumber = request.PhoneNumber,
            UserName = request.PhoneNumber
        };

        respond.NewUser = !await userManager.Users.AnyAsync(x => x.UserName == claimedUser.UserName);

        if (respond.NewUser.Value)
        {
            var result = await userManager.CreateAsync(claimedUser);
            if (!result.Succeeded)
                throw new Exception($"user creation failed: phoneNumber={request.PhoneNumber}");
            await dbContext.SaveChangesAsync();
        }

        claimedUser = await dbContext.Users.FirstAsync(x => x.UserName == request.PhoneNumber);
        respond.HasPassword = claimedUser.PasswordHash != null;

        if (request.RequestOtp.HasValue && request.RequestOtp.Value)
        {
            var codeGenerateResult = await OtpTokenProvider.GenerateOtpAsync(
                userManager, claimedUser, dbContext);
            respond.OptCooldown = codeGenerateResult == null;
            if (!respond.OptCooldown.Value)
                smsService.SendOneTimePassword(claimedUser.PhoneNumber!, codeGenerateResult!);
        }

        await dbContext.SaveChangesAsync();
        return respond;
    }

    #endregion

    #region SigninOtp

    public class SigninOtpRequestModel
    {
        [Required, RegularExpression("^(?:0)?(9\\d{9})$")]
        public string PhoneNumber { set; get; } = "";

        [Required, RegularExpression("^(\\d{6})$")]
        public string Code { set; get; } = "";
    }

    [HttpPost("SigninOtp"), AllowAnonymous]
    public async Task<IActionResult> SigninOtp([FromBody] SigninOtpRequestModel requestModel)
    {
        var claimedUser = new EmadKalaUser
        {
            PhoneNumber = requestModel.PhoneNumber,
            UserName = requestModel.PhoneNumber
        };

        if (!await userManager.Users.AnyAsync(x => x.UserName == claimedUser.UserName))
            return Unauthorized(new { code = "UserNotExist", message = "user not found" });
        claimedUser = await dbContext.Users.FirstAsync(x => x.UserName == requestModel.PhoneNumber);

        var codeGenerateResult = await OtpTokenProvider.ValidateOtpAsync(
            userManager, claimedUser, requestModel.Code, dbContext);
        switch (codeGenerateResult)
        {
            case OtpTokenProvider.VerifyResult.Success:
                var userRoles = await userManager.GetRolesAsync(claimedUser);
                var authClaims = new List<Claim>
                {
                    new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new(JwtRegisteredClaimNames.Name, claimedUser.PhoneNumber!)
                };
                authClaims.AddRange(userRoles.Select(userRole => new Claim(ClaimTypes.Role, userRole)));

                var token = ClaimsToJwt(authClaims);

                await dbContext.SaveChangesAsync();
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });

            case OtpTokenProvider.VerifyResult.WrongCode:
                await dbContext.SaveChangesAsync();
                return Unauthorized(new { code = "WrongCode", message = "wrong otp code" });

            case OtpTokenProvider.VerifyResult.NoRequest:
                return Unauthorized(new { code = "NoRequest", message = "otp code never requested" });

            case OtpTokenProvider.VerifyResult.Expired:
                return Unauthorized(new { code = "Expired", message = "otp code has expired" });

            case OtpTokenProvider.VerifyResult.Cooldown:
                return Unauthorized(new { code = "Cooldown", message = "a cool down is in effect" });

            default:
                throw new Exception("Impossible at SigninOpt");
        }
    }

    private JwtSecurityToken ClaimsToJwt(List<Claim> claims)
    {
        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            configuration["JWT:Secret"] ?? throw new InvalidOperationException()));
        var token = new JwtSecurityToken(
            issuer: configuration["JWT:ValidIssuer"] ?? throw new InvalidOperationException(),
            audience: configuration["JWT:ValidAudience"] ?? throw new InvalidOperationException(),
            expires: DateTime.Now.AddMinutes(
                int.Parse(configuration["JWT:LifetimeMinute"] ?? throw new InvalidOperationException())),
            claims: claims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
        );
        return token;
    }

    #endregion
}
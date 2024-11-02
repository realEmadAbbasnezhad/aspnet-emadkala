using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;

namespace Aspnet_EmadKala.Models;

public class EmadKalaUser : IdentityUser<int>
{
    #region Otp

    [MaxLength(128)] public string? OtpHash { get; set; }

    public DateTime OtpGenerateLastTimeUtc { get; set; }
    public int OtpGenerateCount { get; set; }

    public DateTime OtpValidateLastTimeUtc { get; set; }
    public int OtpValidateFailCount { get; set; }

    #endregion
}

public class EmadKalaRole : IdentityRole<int>
{
}
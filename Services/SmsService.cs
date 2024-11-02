using Microsoft.Extensions.Hosting.Internal;

namespace ShikMelk.WebApp.Services;

public interface ISmsService
{
    public void SendOneTimePassword(string phoneNumber, string password);
}

public class SmsService : ISmsService
{
    public void SendOneTimePassword(string phoneNumber, string password)
    {
        SendRaw(phoneNumber, $"کد ورود شما به عماد کالا\n {password}");
    }

    private void SendRaw(string phoneNumber, string message)
    {
        Console.WriteLine($"{phoneNumber}:{message}");
    }
}
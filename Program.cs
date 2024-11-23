using System.Text;
using Aspnet_EmadKala.Models;
using Aspnet_EmadKala.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using ShikMelk.WebApp.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddCors(opt0 =>
    opt0.AddDefaultPolicy(opt1 => opt1.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

builder.Services.AddControllers();
builder.Services.AddDbContext<DatabaseModel>(opt =>
{
    opt.UseMySQL(builder.Configuration.GetConnectionString("MySqlConnection")
                 ?? throw new InvalidOperationException());
});
builder.Services.AddIdentity<EmadKalaUser, EmadKalaRole>(opt =>
    {
        opt.Lockout.MaxFailedAccessAttempts = 3;
        opt.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
        opt.Lockout.AllowedForNewUsers = true;
    })
    .AddEntityFrameworkStores<DatabaseModel>().AddOtpTokenProvider();
builder.Services.AddTransient<ISmsService, SmsService>();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddCookie(opt => { opt.LoginPath = "/Account/Portal"; })
    .AddJwtBearer(options =>
    {
        options.SaveToken = true;
        options.RequireHttpsMetadata = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidAudience = builder.Configuration["JWT:ValidAudience"] ?? throw new InvalidOperationException(),
            ValidIssuer = builder.Configuration["JWT:ValidIssuer"] ?? throw new InvalidOperationException(),
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]
                                                                               ?? throw new
                                                                                   InvalidOperationException()))
        };
    });

var app = builder.Build();

app.UseCors();
app.MapControllers();
app.UseHttpsRedirection();

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthorization();
app.Services.CreateScope().ServiceProvider.GetService<DatabaseModel>()?.Database.EnsureCreated();

app.Run();
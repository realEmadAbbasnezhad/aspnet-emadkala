using Aspnet_EmadKala.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddDbContext<DatabaseModel>(opt =>
{
    opt.UseMySQL(builder.Configuration.GetConnectionString("MySqlConnection")
                 ?? throw new InvalidOperationException());
});
builder.Services.AddIdentity<EmadKalaUser, EmadKalaRole>().AddEntityFrameworkStores<DatabaseModel>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();
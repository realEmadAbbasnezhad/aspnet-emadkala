using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Aspnet_EmadKala.Models;

public class DatabaseModel(DbContextOptions<DatabaseModel> options) :
    IdentityDbContext<EmadKalaUser, EmadKalaRole, int>(options)
{
    
}

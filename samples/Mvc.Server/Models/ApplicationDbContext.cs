using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Models;

namespace Mvc.Server.Models
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions options)
            : base(options) { }
        
        public DbSet<OpenIddictApplication> OpenIdApplications { get; set; }
        public DbSet<OpenIddictToken> OpenIddictTokens { get; set; }
    }
}

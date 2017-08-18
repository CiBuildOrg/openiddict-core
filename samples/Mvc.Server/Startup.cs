using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AspNet.Security.OAuth.Validation;
using AspNet.Security.OpenIdConnect.Primitives;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Mvc.Server.Models;
using Mvc.Server.Services;
using OpenIddict.Core;
using OpenIddict.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.Internal;
using Microsoft.Extensions.Logging;
using Mvc.Server.Filters;
using Serilog;
using Swashbuckle.AspNetCore.Swagger;

namespace Mvc.Server
{
    public class Startup
    {
        public IConfigurationRoot Configuration { get; set; }

        public Startup(IHostingEnvironment env)
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("config.json", false, true)
                .AddJsonFile($"config.{env.EnvironmentName.ToLower()}.json", true)
                .AddEnvironmentVariables();
            Configuration = configuration.Build();
        }

        public void ConfigureServices(IServiceCollection services)
        {

            // Add Swagger generator
            services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new Info { Title = "My Web API", Version = "v1" });
            });

            //// Add MVC Core
            //services.AddMvcCore(
            //        options =>
            //        {
            //            // Add global authorization filter 
            //            var policy = new AuthorizationPolicyBuilder()
            //                .RequireAuthenticatedUser()
            //                .Build();

            //            options.Filters.Add(new AuthorizeFilter1(policy));

            //            // Add global exception handler for production
            //            options.Filters.Add(typeof(CustomExceptionFilterAttribute));

            //            // Add global validation filter
            //            options.Filters.Add(typeof(ValidateModelFilterAttribute));

            //        }
            //    )
            //    .AddJsonFormatters()
            //    .AddAuthorization()
            //    .AddDataAnnotations()
            //    .AddCors()
            //    .AddApiExplorer();
            services.AddMvc();

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                // Configure the context to use Microsoft SQL Server.
                options.UseSqlServer(Configuration["ConnectionStrings:IdentityContext"]);

                // Register the entity sets needed by OpenIddict.
                // Note: use the generic overload if you need
                // to replace the default OpenIddict entities.
                options.UseOpenIddict();
            });

            Log.Logger = new LoggerConfiguration()
                .ReadFrom.Configuration(Configuration)
                .Enrich.FromLogContext()
                .CreateLogger();

            // Register the Identity services.
            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // Configure Identity to use the same JWT claims as OpenIddict instead
            // of the legacy WS-Federation claims it uses by default (ClaimTypes),
            // which saves you from doing the mapping in your authorization controller.
            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIdConnectConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIdConnectConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIdConnectConstants.Claims.Role;

                options.Password.RequireDigit = false;
                options.Password.RequiredLength = 1;
                options.Password.RequireNonAlphanumeric = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireLowercase = false;
                options.User.AllowedUserNameCharacters = "abcdefghijklmnopqrstuvxyz1234567890!@#$%^&*()_+<>:|";
                options.User.RequireUniqueEmail = false;
                options.SignIn.RequireConfirmedEmail = false;
                options.SignIn.RequireConfirmedPhoneNumber = false;
                options.Lockout.MaxFailedAccessAttempts = 3;
            });

            services.AddAuthentication(options =>
                {
                    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                })

                .AddJwtBearer(options =>
                {
                    options.Authority = "http://localhost:5000";
                    options.Audience = "resource-server";
                    options.RequireHttpsMetadata = false;
                });

           
                // Register the OpenIddict services.
                services.AddOpenIddict(options =>
            {
                // Register the Entity Framework stores.
                options.AddEntityFrameworkCoreStores<ApplicationDbContext>();
                // Register the ASP.NET Core MVC binder used by OpenIddict.
                // Note: if you don't call this method, you won't be able to
                // bind OpenIdConnectRequest or OpenIdConnectResponse parameters.
                options.AddMvcBinders();

                // Enable the authorization, logout, token and userinfo endpoints.
                options.EnableAuthorizationEndpoint("/connect/authorize")
                       .EnableLogoutEndpoint("/connect/logout")
                       .EnableTokenEndpoint("/connect/token")
                       .EnableUserinfoEndpoint("/api/userinfo");

                // Note: the Mvc.Client sample only uses the code flow and the password flow, but you
                // can enable the other flows if you need to support implicit or client credentials.
                options
                       .AllowPasswordFlow()
                       .AllowRefreshTokenFlow();

                options.UseJsonWebTokens();
                options.AddEphemeralSigningKey();
                // Make the "client_id" parameter mandatory when sending a token request.
                options.RequireClientIdentification();
                // During development, you can disable the HTTPS requirement.

                options.DisableHttpsRequirement();
            });

            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();
        }

        // ReSharper disable once UnusedMember.Local
        private static void AddAndConfigurePolicies(IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                // we can make this more granular 
                //options.AddPolicy(AppPolicies.Somepolicy, policy => policy.RequireClaim(AppClaimTypes.SomeClaim));
            });
        }

        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddSerilog();
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseStaticFiles();

            app.UseStatusCodePagesWithReExecute("/error");

            app.UseAuthentication();

            app.UseMvcWithDefaultRoute();

            // Enable middleware to serve generated Swagger as a JSON endpoint.
            app.UseSwagger();

            // Enable middleware to serve swagger-ui (HTML, JS, CSS etc.), specifying the Swagger JSON endpoint.
            app.UseSwaggerUI(c =>
            {
                c.RoutePrefix = "apidocs";
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "My Web API");
            });


            // Seed the database with the sample applications.
            // Note: in a real world application, this step should be part of a setup script.
            InitializeAsync(app.ApplicationServices, CancellationToken.None).GetAwaiter().GetResult();
        }

        private static async Task InitializeAsync(IServiceProvider services, CancellationToken cancellationToken)
        {
            // Create a new service scope to ensure the database context is correctly disposed when this methods returns.
            using (var scope = services.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                await context.Database.EnsureCreatedAsync(cancellationToken);

                var manager = scope.ServiceProvider.GetRequiredService<OpenIddictApplicationManager<OpenIddictApplication>>();

                if (await manager.FindByClientIdAsync("mvc", cancellationToken) == null)
                {
                    var application = new OpenIddictApplication
                    {
                        ClientId = "mvc",
                        DisplayName = "MVC client application",
                        LogoutRedirectUri = "http://localhost:53507/signout-callback-oidc",
                        RedirectUri = "http://localhost:53507/signin-oidc"
                    };

                    await manager.CreateAsync(application, "901564A5-E7FE-42CB-B10D-61EF6A8F3654", cancellationToken);
                }

                // To test this sample with Postman, use the following settings:
                //
                // * Authorization URL: http://localhost:54540/connect/authorize
                // * Access token URL: http://localhost:54540/connect/token
                // * Client ID: postman
                // * Client secret: [blank] (not used with public clients)
                // * Scope: openid email profile roles
                // * Grant type: authorization code
                // * Request access token locally: yes
                if (await manager.FindByClientIdAsync("postman", cancellationToken) == null)
                {
                    var application = new OpenIddictApplication
                    {
                        ClientId = "postman",
                        DisplayName = "Postman",
                        RedirectUri = "https://www.getpostman.com/oauth2/callback"
                    };

                    await manager.CreateAsync(application, cancellationToken);
                }
            }
        }
    }


    /// <summary>
    /// An implementation of <see cref="T:Microsoft.AspNetCore.Mvc.Filters.IAsyncAuthorizationFilter" /> which applies a specific
    /// <see cref="T:Microsoft.AspNetCore.Authorization.AuthorizationPolicy" />. MVC recognizes the <see cref="T:Microsoft.AspNetCore.Authorization.AuthorizeAttribute" /> and adds an instance of
    /// this filter to the associated action or controller.
    /// </summary>
    public class AuthorizeFilter1 : IAsyncAuthorizationFilter, IFilterFactory
    {
        /// <summary>
        /// The <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizationPolicyProvider" /> to use to resolve policy names.
        /// </summary>
        public IAuthorizationPolicyProvider PolicyProvider { get; }

        /// <summary>
        /// The <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizeData" /> to combine into an <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizeData" />.
        /// </summary>
        public IEnumerable<IAuthorizeData> AuthorizeData { get; }

        /// <summary>Gets the authorization policy to be used.</summary>
        /// <remarks>
        /// If<c>null</c>, the policy will be constructed using
        /// <see cref="M:Microsoft.AspNetCore.Authorization.AuthorizationPolicy.CombineAsync(Microsoft.AspNetCore.Authorization.IAuthorizationPolicyProvider,System.Collections.Generic.IEnumerable{Microsoft.AspNetCore.Authorization.IAuthorizeData})" />.
        /// </remarks>
        public AuthorizationPolicy Policy { get; }

        bool IFilterFactory.IsReusable => true;

        /// <summary>
        /// Initialize a new <see cref="T:Microsoft.AspNetCore.Mvc.Authorization.AuthorizeFilter" /> instance.
        /// </summary>
        /// <param name="policy">Authorization policy to be used.</param>
        public AuthorizeFilter1(AuthorizationPolicy policy)
        {
            Policy = policy ?? throw new ArgumentNullException(nameof(policy));
        }

        /// <summary>
        /// Initialize a new <see cref="T:Microsoft.AspNetCore.Mvc.Authorization.AuthorizeFilter" /> instance.
        /// </summary>
        /// <param name="policyProvider">The <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizationPolicyProvider" /> to use to resolve policy names.</param>
        /// <param name="authorizeData">The <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizeData" /> to combine into an <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizeData" />.</param>
        public AuthorizeFilter1(IAuthorizationPolicyProvider policyProvider, IEnumerable<IAuthorizeData> authorizeData)
            : this(authorizeData)
        {
            PolicyProvider = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
        }

        /// <summary>
        /// Initializes a new instance of <see cref="T:Microsoft.AspNetCore.Mvc.Authorization.AuthorizeFilter" />.
        /// </summary>
        /// <param name="authorizeData">The <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizeData" /> to combine into an <see cref="T:Microsoft.AspNetCore.Authorization.IAuthorizeData" />.</param>
        public AuthorizeFilter1(IEnumerable<IAuthorizeData> authorizeData)
        {
            AuthorizeData = authorizeData ?? throw new ArgumentNullException(nameof(authorizeData));
        }

        /// <summary>
        /// Initializes a new instance of <see cref="T:Microsoft.AspNetCore.Mvc.Authorization.AuthorizeFilter" />.
        /// </summary>
        /// <param name="policy">The name of the policy to require for authorization.</param>
        public AuthorizeFilter1(string policy)
            : this(new[]
            {
                new AuthorizeAttribute(policy)
            })
        {
        }

        /// <inheritdoc />
        public virtual async Task OnAuthorizationAsync(AuthorizationFilterContext context)
        {
            var filters = context.Filters;

            var descriptor = context?.ActionDescriptor as ControllerActionDescriptor;
            if (descriptor != null)
            {
                var attributes = descriptor.MethodInfo.GetCustomAttributes(true);
                var routeAttribute = attributes.SingleOrDefault(x => x.GetType() == typeof(RouteAttribute));

                if (routeAttribute != null)
                {
                    var attribute = (RouteAttribute)routeAttribute;

                    if (attribute.Template == "~/error")
                        return;
                }

                // if we ever have allowAnonymous on methods 
                if (attributes.Any(x => x.GetType() == typeof(AllowAnonymousAttribute)))
                {
                    return;
                }

                var authorizeAttribute = attributes.SingleOrDefault(x => x.GetType() == typeof(AuthorizeAttribute));
                if (authorizeAttribute != null)
                {
                    var attribute = (AuthorizeAttribute) authorizeAttribute;
                    if (attribute.AuthenticationSchemes == OAuthValidationDefaults.AuthenticationScheme)
                    {
                        return;
                    }
                }
            }

            bool Func(IFilterMetadata item) => item is IAllowAnonymousFilter;
            if (filters.Any(Func))
                return;

            if (context == null)
                throw new ArgumentNullException(nameof(context));
            var effectivePolicy = Policy;
            if (effectivePolicy == null)
            {
                if (PolicyProvider == null)
                    throw new InvalidOperationException("Auth policy cannot be created");
                effectivePolicy = await AuthorizationPolicy.CombineAsync(PolicyProvider, AuthorizeData);
            }
            if (effectivePolicy == null)
                return;
            var policyEvaluator = context.HttpContext.RequestServices.GetRequiredService<IPolicyEvaluator>();
            var authenticationResult = await policyEvaluator.AuthenticateAsync(effectivePolicy, context.HttpContext);

            

            var authorizationResult = await policyEvaluator.AuthorizeAsync(effectivePolicy, authenticationResult, context.HttpContext, context);
            if (authorizationResult.Challenged)
            {
                context.Result = new ChallengeResult(effectivePolicy.AuthenticationSchemes.ToArray());
            }
            else
            {
                if (!authorizationResult.Forbidden)
                    return;
                context.Result = new ForbidResult(effectivePolicy.AuthenticationSchemes.ToArray());
            }
        }

        IFilterMetadata IFilterFactory.CreateInstance(IServiceProvider serviceProvider)
        {
            if (Policy != null || PolicyProvider != null)
                return this;
            return AuthorizationApplicationModelProvider.GetFilter(serviceProvider.GetRequiredService<IAuthorizationPolicyProvider>(), AuthorizeData);
        }
    }
}

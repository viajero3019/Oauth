using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Server.Extensions;

public static class AuthExtensions
{
    public static IServiceCollection AddMyTokenAuthentication(this IServiceCollection services)
    {
        services.AddAuthentication("Oauth")
            .AddJwtBearer("Oauth", config =>
            {
                var secretBytes = Encoding.UTF8.GetBytes(SecretConstants.Secret);
                var key = new SymmetricSecurityKey(secretBytes);

                config.Events = new JwtBearerEvents()
                {
                    OnMessageReceived = context =>
                    {
                        // This is to check a Token has been passed trough the Url as a parameter
                        if (context.Request.Query.ContainsKey("access_token"))
                        {
                            // Asigns Received token to the context
                            context.Token = context.Request.Query["access_token"];
                        }
                        return Task.CompletedTask;
                    }
                };

                config.TokenValidationParameters = new TokenValidationParameters()
                {
                    ValidIssuer = SecretConstants.Issuer,
                    ValidAudience = SecretConstants.Audiance,
                    IssuerSigningKey = key  // For this example, this must match with the generated key in HomeController
                };
            });
        return services;
    }
}
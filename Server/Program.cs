using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using Server;
using Server.Extensions;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddMyTokenAuthentication();

builder.Services.AddControllersWithViews();



//////////////////////////////////////////////////////////////////

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseEndpoints(endpoint =>
{
    endpoint.MapDefaultControllerRoute();
});

app.Run();

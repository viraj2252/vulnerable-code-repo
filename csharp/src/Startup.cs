using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;

namespace VulnerableDotNetApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // VULNERABILITY: Insecure serialization settings
            services.AddControllers().AddNewtonsoftJson(options => 
            {
                // VULNERABILITY: TypeNameHandling.All is dangerous
                options.SerializerSettings.TypeNameHandling = TypeNameHandling.All;
                options.SerializerSettings.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;
            });

            // VULNERABILITY: No CORS policy
            services.AddCors(options =>
            {
                options.AddDefaultPolicy(builder =>
                {
                    // VULNERABILITY: Allow all origins, methods, and headers
                    builder.AllowAnyOrigin()
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                });
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            // VULNERABILITY: Development mode in production
            if (true || env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            // VULNERABILITY: No HTTPS redirection
            // app.UseHttpsRedirection();

            app.UseRouting();

            // VULNERABILITY: No authentication
            // app.UseAuthentication();

            // VULNERABILITY: No authorization
            // app.UseAuthorization();

            // VULNERABILITY: CORS policy allows all origins
            app.UseCors();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
} 
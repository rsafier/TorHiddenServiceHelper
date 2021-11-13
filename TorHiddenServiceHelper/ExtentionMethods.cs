using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TorHiddenServiceHelper.ExtentionMethods
{
    public static class ExtentionMethods
    {
        public static void AddInjectableHostedService<TService, TImplementation>(this IServiceCollection services, Func<IServiceProvider,TImplementation> IServiceProvider)
            where TService : class
            where TImplementation : class, IHostedService, TService
        {
            services.AddSingleton<TImplementation>(x => IServiceProvider(x));
            services.AddSingleton<IHostedService>(provider => provider.GetRequiredService<TImplementation>());
            services.AddSingleton<TService>(provider => provider.GetRequiredService<TImplementation>());
        }
        public static void AddInjectableHostedService<TService, TImplementation>(this IServiceCollection services)
           where TService : class
           where TImplementation : class, IHostedService, TService
        {
            services.AddSingleton<TImplementation>();
            services.AddSingleton<IHostedService>(provider => provider.GetRequiredService<TImplementation>());
            services.AddSingleton<TService>(provider => provider.GetRequiredService<TImplementation>());
        }
    }
}

using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using StackExchange.Redis;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace DataProtection
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var RedisConnection = "127.0.0.1:6379,abortConnect=false,KeepAlive=180,password=redis123";
            Console.WriteLine("Hello World!");
            var builder = new HostBuilder()
                .ConfigureServices((hostContext, services) =>
                {
                    services.AddDataProtection().SetApplicationName("DataProtection").PersistKeysToStackExchangeRedis(ConnectionMultiplexer.Connect(RedisConnection), "DataProtection-Keys").ProtectKeysWithAES();
                    services.AddHostedService<TestDataProtection>();
                });
            await builder.RunConsoleAsync();
        }
    }
    public class TestDataProtection : BackgroundService
    {
        IDataProtector dataProtector;
        public TestDataProtection(IDataProtectionProvider dataProtectionProvider)
        {
            dataProtector = dataProtectionProvider.CreateProtector("TestDataProtection");
        }
        protected override Task ExecuteAsync(CancellationToken stoppingToken)
        {
            Console.WriteLine(dataProtector.Protect("Hello World!"));
            return Task.CompletedTask;
        }
    }
}

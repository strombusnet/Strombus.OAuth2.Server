using Strombus.Redis;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Strombus.OAuth2.Server
{
    public sealed class Singletons
    {
        private static volatile RedisClient _redisClient;
        private static SemaphoreSlim _redisClientSyncLock = new SemaphoreSlim(1, 1);
        private const string REDIS_SERVER_HOSTNAME = "127.0.0.1";

        private const long REDIS_DATABASE_INDEX_OAUTH2SERVICE = 1;

        private Singletons() { }

        public static async Task<RedisClient> GetRedisClientAsync()
        {
            // NOTE: as an optimization for frequent accesses, we check to see if the redis client exists before locking on its sync object.
            if (_redisClient == null)
            {
                await _redisClientSyncLock.WaitAsync();
                try
                {
                    // NOTE: if the previous caller was blocked on .WaitAsync() because the singleton was being created, once it is unblocked this code block will be skipped.
                    if (_redisClient == null)
                    {
                        RedisClient redisClient = new RedisClient();
                        await redisClient.ConnectAsync(REDIS_SERVER_HOSTNAME);
                        await redisClient.EnablePipelineAsync();
                        await redisClient.SelectAsync(REDIS_DATABASE_INDEX_OAUTH2SERVICE);
                        _redisClient = redisClient;
                    }
                }
                finally
                {
                    _redisClientSyncLock.Release();
                }
            }
            return _redisClient;
        }
    }
}

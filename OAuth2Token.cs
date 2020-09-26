using Strombus.Redis;
using Strombus.ServerShared;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace Strombus.OAuth2.Server
{
    public class OAuth2Token
    {
        // Definitions:
        // ORIGIN SERVER: the server which owns and mantains the token and its associated credentials
        // AUTHORITATIVE SERVER: servers in the same cluster as the origin server--which are the origin server or secondary trusted copies of the token
        // CACHED TOKEN: store a local copy of the token and its credentials and subscribe to token change/revoke notifications.  This is useful for servers who have resources owned by the token owner.

        static RedisClient _redisClient = null;

        private const string REDIS_PREFIX_ACCOUNT = "account";
        private const string REDIS_PREFIX_OAUTH2TOKEN = "oauth2token";
        private const string REDIS_PREFIX_USER = "user";
        private const string REDIS_PREFIX_SEPARATOR = ":";
        //
        private const string REDIS_SLASH = "/";
        //
        private const string REDIS_SUFFIX_HIGHTRUST_OAUTH2TOKENS = "hightrust-oauth2tokens";
        private const string REDIS_SUFFIX_OAUTH2TOKENS = "oauth2tokens";
        private const string REDIS_SUFFIX_SCOPES = "scopes";
        private const string REDIS_SUFFIX_SEPARATOR = "#";

        public enum TokenStorageOptions
        {
            Authoritative = 0,
            Cached = 1,
            TemporaryCopy = 2,
        }

        private string _authServerId;

        private string _id;
        private DateTimeOffset? _expirationTime;
        bool _expirationTime_IsDirty = false;
        private string _refreshTokenId;
        bool _refreshTokenId_IsDirty = false;
        private ListWithDirtyFlag<string> _scopes;
        private string _clientId;
        private bool _clientId_IsDirty = false;
        private string _accountId;
        private bool _accountId_IsDirty = false;
        private string _userId;
        private bool _userId_IsDirty = false;
        private TokenStorageOptions _tokenStorage;
        private Int64? _timeCreatedInUnixMicroseconds; // null for new objects; otherwise the creation timestamp when the object was saved by redis
        private Int64? _timeUpdatedInUnixMicroseconds; // null for new objects; otherwise the last timestamp that the object was saved by redis

        private OAuth2Token()
        {
        }

        public static async Task<OAuth2Token> LoadTokenAsync(string tokenId)
        {
            // default operation: attempt to retrieve the token from the origin server if necessary.
            return await LoadTokenAsync(tokenId, false).ConfigureAwait(false);
        }

        // NOTE: if localOnly is set to false, the caller MUST catch System.Net.Sockets.SocketException (which indicates that we could not communicate with the origin token cluster).
        public static async Task<OAuth2Token> LoadTokenAsync(string tokenId, bool localOnly)
        {
            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            string fullyQualifiedTokenKey = REDIS_PREFIX_OAUTH2TOKEN + REDIS_PREFIX_SEPARATOR + tokenId;
            bool localTokenExists = (await _redisClient.ExistsAsync(new string[] { fullyQualifiedTokenKey }) > 0);
            if (localTokenExists)
            {
                Dictionary<string, string> tokenDictionary = await _redisClient.HashGetAllASync<string, string, string>(fullyQualifiedTokenKey);

                string tokenIsCachedAsString = tokenDictionary.ContainsKey("cached") ? tokenDictionary["cached"] : null;
                bool tokenIsCached = (tokenIsCachedAsString != null && tokenIsCachedAsString != "0");

                string timeCreatedAsString = tokenDictionary.ContainsKey("time-created") ? tokenDictionary["time-created"] : null;
                Int64? timeCreatedInUnixMicroseconds = null;
                Int64 timeCreatedAsInt64;
                if (timeCreatedAsString != null && Int64.TryParse(timeCreatedAsString, out timeCreatedAsInt64))
                {
                    timeCreatedInUnixMicroseconds = timeCreatedAsInt64;
                }

                string timeUpdatedAsString = tokenDictionary.ContainsKey("time-updated") ? tokenDictionary["time-updated"] : null;
                Int64? timeUpdatedInUnixMicroseconds = null;
                Int64 timeUpdatedAsInt64;
                if (timeUpdatedAsString != null && Int64.TryParse(timeUpdatedAsString, out timeUpdatedAsInt64))
                {
                    timeUpdatedInUnixMicroseconds = timeUpdatedAsInt64;
                }

                OAuth2Token resultToken = new OAuth2Token();
                resultToken._clientId = tokenDictionary.ContainsKey("client-id") ? tokenDictionary["client-id"] : null;
                if (resultToken._clientId == null)
                {
                    return null;
                }
                resultToken._accountId = tokenDictionary.ContainsKey("account-id") ? tokenDictionary["account-id"] : null;
                if (resultToken._accountId == null)
                {
                    return null;
                }
                resultToken._userId = tokenDictionary.ContainsKey("user-id") ? tokenDictionary["user-id"] : null;

                long? expirationTimeInUnixSeconds = tokenDictionary.ContainsKey("expiration-time") ? long.Parse(tokenDictionary["expiration-time"]) : (long?)null;
                resultToken._expirationTime = expirationTimeInUnixSeconds != null ? DateTimeOffset.FromUnixTimeSeconds(expirationTimeInUnixSeconds.Value) : (DateTimeOffset?)null;
                //
                resultToken._refreshTokenId = tokenDictionary.ContainsKey("refresh-token-id") ? tokenDictionary["refresh-token-id"] : null;
                //
                resultToken._scopes = await _redisClient.SetMembersAsync<string, string>(fullyQualifiedTokenKey + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_SCOPES).ConfigureAwait(false);

                // if our result token could be loaded, populate the default fields common to all OAuth2Tokens.
                resultToken._id = tokenId;
                resultToken._tokenStorage = tokenIsCached ? TokenStorageOptions.Cached : TokenStorageOptions.Authoritative;

                resultToken._timeCreatedInUnixMicroseconds = timeCreatedInUnixMicroseconds;
                resultToken._timeUpdatedInUnixMicroseconds = timeUpdatedInUnixMicroseconds;

                return resultToken;
            }

            if (!localOnly)
            {
                /* if we have not retrieved a token locally, search for token at the origin server (and, if that fails, in the origin server's cluster) */
                OAuth2Token resultToken = await RemoteRequestTokenAsync(tokenId);
                return resultToken;
            }

            // valid token could not be found
            return null;
        }

        private struct ExtractAccountIdAndServerIdFromTokenResult
        {
            public string AccountId;
            public string AccountServerId;
        }
        private static ExtractAccountIdAndServerIdFromTokenResult? ExtractAccountIdAndServerIdFromToken(string tokenId)
        {
            if (tokenId == null)
            {
                return null;
            }

            if (tokenId.IndexOf('-') >= 0)
            {
                // retrieve the account id
                string firstValue = tokenId.Substring(0, tokenId.IndexOf('-'));
                // remove the first value from the token
                tokenId = tokenId.Substring(tokenId.IndexOf("-") + 1);

                // verify that the first value (account id) is not a number; that would mean that we're looking at a root token instead of an account token
                if (firstValue.All(char.IsDigit))
                {
                    return new ExtractAccountIdAndServerIdFromTokenResult() { AccountId = null, AccountServerId = firstValue };
                }

                // verify that the first value is a valid account name (i.e. does not contain invalid characters)
                if (firstValue != null && FormattingHelper.ContainsOnlyAllowedIdentifierCharacters(firstValue) == false)
                {
                    return null;
                }

                if (tokenId.IndexOf('-') >= 0)
                {
                    string secondValue = tokenId.Substring(0, tokenId.IndexOf('-'));
                    // verify that the second value is a number (i.e. the server id)
                    if (secondValue.All(char.IsDigit))
                    {
                        return new ExtractAccountIdAndServerIdFromTokenResult { AccountId = firstValue, AccountServerId = secondValue };
                    }
                }
            }

            // if we reach here, the token is not valid
            return null;
        }

        struct RemoteRequestTokenResponse
        {
            public string id;
            public DateTimeOffset? expiration_time;
            public string refresh_token;
            public List<string> scopes;
            public string client_id;
            public string account_id;
            public string user_id;
        }
        public static async Task<OAuth2Token> RemoteRequestTokenAsync(string tokenId)
        {
            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            // client certificate is a fixed value for our server
            string clientCertificateDn = "/C=US/ST=Washington/L=Seattle/O=Strombus LLC/OU=Web Security/CN=servername-1.example.com";

            // accountId is token-specific
            ExtractAccountIdAndServerIdFromTokenResult? tokenHostnameParts = ExtractAccountIdAndServerIdFromToken(tokenId);
            if (tokenHostnameParts == null) return null;
            string accountId = tokenHostnameParts.Value.AccountId;
            string accountServerId = tokenHostnameParts.Value.AccountServerId;

            string serverHostname;

            /* retrieve account-specific server-to-server auth token from our local Redis instance. */
            string fullyQualifiedHighTrustTokenKey = REDIS_PREFIX_ACCOUNT + REDIS_PREFIX_SEPARATOR + accountId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_HIGHTRUST_OAUTH2TOKENS;
            string fieldName = "login";
            string serverToServerAuthToken = await _redisClient.HashGetAsync<string, string, string>(fullyQualifiedHighTrustTokenKey, fieldName);

            if (serverToServerAuthToken == null)
            {
                return null;
            }

            // NOTE: on the first attempt, we try calling the specific server; if that fails, we retry by calling the account's login cluster
            int iAttempt = 0;
            int maxAttempts = 1;
            while (iAttempt < maxAttempts)
            {
                serverHostname = accountId != null ? accountId + "-login" : "login";
                if (iAttempt == 0 && accountServerId != null)
                {
                    serverHostname += "-" + accountServerId;
                    maxAttempts++; // if the token is for a specific account's server (the standard case) then try the specific server first...before trying the cluster.
                }
                serverHostname += ".example.com";
                string requestUriAsString = "https://" + serverHostname + "/oauth2/token/" + tokenId;
                try
                {
                    using (HttpClient httpClient = new HttpClient())
                    {
                        // create request
                        var requestMessage = new HttpRequestMessage(HttpMethod.Get, requestUriAsString);
                        requestMessage.Headers.Accept.Clear();
                        requestMessage.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/json"));
                        requestMessage.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", serverToServerAuthToken);
                        //
                        /* TODO: this is temporary; be sure to replace with an actual client certificate in the future, use port 5443, and disable this header for port 443 on the target */
                        requestMessage.Headers.Add("X-SSL-Client-S-DN", clientCertificateDn);
                        // send request
                        HttpResponseMessage responseMessage = await httpClient.SendAsync(requestMessage);

                        // process response
                        switch (responseMessage.StatusCode)
                        {
                            case HttpStatusCode.OK:
                                {
                                    // token was retrieved; parse response.
                                    RemoteRequestTokenResponse responsePayload = JsonConvert.DeserializeObject<RemoteRequestTokenResponse>(await responseMessage.Content.ReadAsStringAsync());
                                    OAuth2Token result = new OAuth2Token();
                                    result._id = responsePayload.id;
                                    result._tokenStorage = TokenStorageOptions.TemporaryCopy;
                                    result._expirationTime = responsePayload.expiration_time;
                                    result._refreshTokenId = responsePayload.refresh_token;
                                    result._scopes = responsePayload.scopes;
                                    result._clientId = responsePayload.client_id;
                                    result._accountId = responsePayload.account_id;
                                    result._userId = responsePayload.user_id;
                                    return result;
                                }
                            default:
                                return null;
                        }
                    }
                }
                catch (Exception ex)
                {
                    if (iAttempt == 1)
                    {
                        throw ex;
                    }
                }
                iAttempt++;
            }

            // default: return null
            return null;
        }

        public static OAuth2Token NewToken(string authServerId)
        {
            OAuth2Token result = new OAuth2Token()
            {
                _authServerId = authServerId,
                _id = null,
                //
                _accountId = null,
                _accountId_IsDirty = false,
                //
                _clientId = null,
                _clientId_IsDirty = false,
                //
                _userId = null,
                _userId_IsDirty = false,
                //
                _expirationTime = null,
                _expirationTime_IsDirty = false,
                //
                _refreshTokenId = null,
                _refreshTokenId_IsDirty = false,
                //
                _scopes = new ListWithDirtyFlag<string>(),
                _tokenStorage = TokenStorageOptions.Authoritative,
            };
            return result;
        }

        public async Task SaveTokenAsync()
        {
            // we only support saving a local token (i.e. not updating a remote token)
            if (_tokenStorage != TokenStorageOptions.Authoritative) throw new InvalidOperationException();

            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            bool objectIsNew = (_timeCreatedInUnixMicroseconds == null);

            int RESULT_KEY_CONFLICT = -1;
            int RESULT_DATA_CORRUPTION = -2;
            int RESULT_UPDATED_SINCE_LOAD = -3;

            // get current server time
            long newTimeUpdatedInUnixMicroseconds = await _redisClient.TimeAsync();
            if (newTimeUpdatedInUnixMicroseconds < 0)
            {
                throw new Exception("Critical Redis error!");
            }
            if (newTimeUpdatedInUnixMicroseconds < _timeUpdatedInUnixMicroseconds)
            {
                throw new Exception("Critical Redis error!");
            }

            // generate Lua script (which we will use to commit all changes--or the new record--in an atomic transaction)
            StringBuilder luaBuilder = new StringBuilder();
            List<string> arguments = new List<string>();
            int iArgument = 1;
            if (objectIsNew)
            {
                // for new tokens: if a token with this token-id already exists, return 0...and we will try again.
                luaBuilder.Append(
                    "if redis.call(\"EXISTS\", KEYS[1]) == 1 then\n" +
                    "  return " + RESULT_KEY_CONFLICT.ToString() + "\n" +
                    "end\n");
            }
            else
            {
                // for updated: make sure that the "time-created" timestamp has not changed (i.e. that a new key has not replaced the old key)
                luaBuilder.Append("local time_created = redis.call(\"HGET\", KEYS[1], \"time-created\")\n");
                luaBuilder.Append("if time_created ~= ARGV[" + iArgument.ToString() + "] then\n" +
                    "  return " + RESULT_KEY_CONFLICT.ToString() + "\n" +
                    "end\n");
                arguments.Add(_timeCreatedInUnixMicroseconds.ToString());
                iArgument++;

                // for updates: make sure that our old "time-updated" timestamp has not changed
                luaBuilder.Append("local old_time_updated = redis.call(\"HGET\", KEYS[1], \"time-updated\")\n");
                luaBuilder.Append("if old_time_updated ~= ARGV[" + iArgument.ToString() + "] then\n" +
                    "  return " + RESULT_UPDATED_SINCE_LOAD.ToString() + "\n" +
                    "end\n");
                arguments.Add(_timeUpdatedInUnixMicroseconds.ToString());
                iArgument++;
            }
            //
            if (objectIsNew)
            {
                luaBuilder.Append(
                    "if redis.call(\"HSET\", KEYS[1], \"time-created\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                    "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                    "end\n");
                arguments.Add(newTimeUpdatedInUnixMicroseconds.ToString());
                iArgument++;
            }
            //
            luaBuilder.Append(
                "if redis.call(\"HSET\", KEYS[1], \"time-updated\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                "end\n");
            arguments.Add(newTimeUpdatedInUnixMicroseconds.ToString());
            iArgument++;
            //
            if (_clientId_IsDirty)
            {
                if (_clientId != null)
                {
                    // if there is a client-id assigned to this token, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"client-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_clientId);
                    iArgument++;
                }
                else
                {
                    // if the client-id has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"client-id\")\n");
                }
                // clear the dirty flag
                _clientId_IsDirty = false;
            }
            //
            if (_accountId_IsDirty)
            {
                if (_accountId != null)
                {
                    // if there is an account-id assigned to this token, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"account-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_accountId);
                    iArgument++;
                }
                else
                {
                    // if the account-id has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"account-id\")\n");
                }
                // clear the dirty flag
                _accountId_IsDirty = false;
            }
            //
            if (_userId_IsDirty)
            {
                if (_userId != null)
                {
                    // if there is a user-id assigned to this token, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"user-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_userId);
                    iArgument++;
                }
                else
                {
                    // if the user-id has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"user-id\")\n");
                }
                // clear the dirty flag
                _userId_IsDirty = false;
            }
            //
            if (_expirationTime_IsDirty)
            {
                if (_expirationTime != null)
                {
                    // if there is an expiration assigned to this token, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"expiration-time\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_expirationTime.Value.ToUnixTimeSeconds().ToString());
                    iArgument++;
                }
                else
                {
                    // if the expiration has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"expiration-time\")\n");
                }
                // clear the dirty flag
                _expirationTime_IsDirty = false;
            }
            if (_refreshTokenId_IsDirty)
            {
                if (_refreshTokenId != null)
                {
                    // if there is a refresh_token assigned to this token, save it.
                    luaBuilder.Append(
                        "if redis.call(\"HSET\", KEYS[1], \"refresh-token-id\", ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(_refreshTokenId);
                    iArgument++;
                }
                else
                {
                    // if the refresh_token has been removed, delete it.
                    luaBuilder.Append("redis.call(\"HDEL\", KEYS[1], \"refresh-token-id\")\n");
                }
                // clear the dirty flag
                _refreshTokenId_IsDirty = false;
            }
            // populate the set of scopes
            if (_scopes.IsDirty)
            {
                luaBuilder.Append(objectIsNew ? "" : "redis.call(\"DEL\", KEYS[2])\n");
                foreach (string scope in _scopes)
                {
                    luaBuilder.Append(
                        "if redis.call(\"SADD\", KEYS[2], ARGV[" + iArgument.ToString() + "]) == 0 then\n" +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[1])\n" : "") +
                        (objectIsNew ? "  redis.call(\"DEL\", KEYS[2])\n" : "") +
                        "  return " + RESULT_DATA_CORRUPTION.ToString() + "\n" +
                        "end\n");
                    arguments.Add(scope);
                    iArgument++;
                }

                // clear the dirty flag
                _scopes.IsDirty = false;
            }
            //
            luaBuilder.Append("return 1\n");

            long luaResult = 0;
            for (int iRetry = 0; iRetry < (objectIsNew ? 1000 : 1); iRetry++)
            {
                if (objectIsNew)
                {
                    // generate a 32-byte (192-bit) token_id
                    _id = _authServerId + "-" + (new string(RandomHelper.CreateRandomCharacterSequence_Readable6bit_ForIdentifiers(32)));
                }
                List<string> keys = new List<string>();
                keys.Add(REDIS_PREFIX_OAUTH2TOKEN + REDIS_PREFIX_SEPARATOR + _id);
                keys.Add(REDIS_PREFIX_OAUTH2TOKEN + REDIS_PREFIX_SEPARATOR + _id + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_SCOPES);
                luaResult = await _redisClient.EvalAsync<string, string, long>(luaBuilder.ToString(), keys.ToArray(), arguments.ToArray()).ConfigureAwait(false);
                // if we were able to create a key, break out of this loop; otherwise, try generating new keys up to 1000 times.
                if (luaResult == 1)
                {
                    // save our "time-updated" timestamp
                    _timeUpdatedInUnixMicroseconds = newTimeUpdatedInUnixMicroseconds;

                    if (objectIsNew)
                    {
                        // save our "time-created" timestamp
                        _timeCreatedInUnixMicroseconds = newTimeUpdatedInUnixMicroseconds;

                        // assign the tokens to its accounts/users now.
                        if (_userId != null)
                        {
                            // if the token belongs to a user (and not more generally to an account), add it to the user's token collection.
                            await _redisClient.SetAddAsync<string, string>(REDIS_PREFIX_USER + REDIS_PREFIX_SEPARATOR + _accountId + REDIS_SLASH + _userId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS, new string[] { _id });
                        }
                        else if (_accountId != null)
                        {
                            // if the token belongs to the account (and not to the user), add it to the account's token collection.
                            await _redisClient.SetAddAsync<string, string>(REDIS_PREFIX_ACCOUNT + REDIS_PREFIX_SEPARATOR + _accountId + REDIS_SUFFIX_SEPARATOR + REDIS_SUFFIX_OAUTH2TOKENS, new string[] { _id });
                        }
                    }
                    break;
                }
                else if (luaResult == RESULT_KEY_CONFLICT)
                {
                    // key name conflict; try again
                }
                else if (luaResult == RESULT_DATA_CORRUPTION)
                {
                    // data corruption
                    throw new Exception("Critical Redis error!");
                }
                else if (luaResult == RESULT_UPDATED_SINCE_LOAD)
                {
                    // token was updated since we loaded it; we need to reload the token, make the changes again, and then attempt to save it again
                    throw new Exception("Critical Redis error!");
                }
                else
                {
                    // unknown error
                    throw new Exception("Critical Redis error!");
                }
            }

            if (luaResult < 0)
            {
                throw new Exception("Critical Redis error!");
            }
        }

        public async Task DeleteTokenAsync()
        {
            // we only support saving a local token (i.e. not updating a remote token)
            if (_tokenStorage != TokenStorageOptions.Authoritative) throw new InvalidOperationException();
            // we cannot delete a token which has not yet been created
            if (_timeCreatedInUnixMicroseconds == null) return;

            if (_redisClient == null)
            {
                _redisClient = await Singletons.GetRedisClientAsync();
            }

            int RESULT_KEY_CONFLICT = -1;

            // generate Lua script (which we will use to commit all changes--or the new record--in an atomic transaction)
            StringBuilder luaBuilder = new StringBuilder();
            List<string> arguments = new List<string>();
            int iArgument = 1;
            // if the token has already been deleted, return success
            luaBuilder.Append(
                "if redis.call(\"EXISTS\", KEYS[1]) == 0 then\n" +
                "  return 1\n" +
                "end\n");
            // for deletions: make sure that the "time-created" timestamp has not changed (i.e. that a new key has not replaced the old key)
            luaBuilder.Append("local time_created = redis.call(\"HGET\", KEYS[1], \"time-created\")\n");
            luaBuilder.Append("if time_created ~= ARGV[" + iArgument.ToString() + "] then\n" +
                "  return " + RESULT_KEY_CONFLICT.ToString() + "\n" +
                "end\n");
            arguments.Add(_timeCreatedInUnixMicroseconds.ToString());
            iArgument++;
            //
            luaBuilder.Append(
                "redis.call(\"DEL\", KEYS[1])\n");
            // 
            luaBuilder.Append("return 1\n");

            long luaResult = 0;
            List<string> keys = new List<string>();
            keys.Add(REDIS_PREFIX_OAUTH2TOKEN + REDIS_PREFIX_SEPARATOR + _id);
            luaResult = await _redisClient.EvalAsync<string, string, long>(luaBuilder.ToString(), keys.ToArray(), arguments.ToArray()).ConfigureAwait(false);

            // NOTE: the result will contain a negative integer (error) or positive one (success)
            if (luaResult == 1)
            {
                // reset our server-assigned values
                _timeCreatedInUnixMicroseconds = null;
                _timeUpdatedInUnixMicroseconds = null;
                _id = null;
                _tokenStorage = TokenStorageOptions.Authoritative;
            }
            else if (luaResult == RESULT_KEY_CONFLICT)
            {
                // key name conflict; abort
                return;
            }
            else
            {
                // unknown error
                throw new Exception("Critical Redis error!");
            }

            if (luaResult < 0)
            {
                throw new Exception("Critical Redis error!");
            }

            /* TODO: raise the appropriate events (token deleted) */
        }

        public string Id
        {
            get
            {
                return _id;
            }
        }

        public DateTimeOffset? ExpirationTime
        {
            get
            {
                return _expirationTime;
            }
            set
            {
                if (_expirationTime != value)
                {
                    _expirationTime = value;
                    _expirationTime_IsDirty = true;
                }
            }
        }

        public string RefreshTokenId
        {
            get
            {
                return _refreshTokenId;
            }
            set
            {
                if (_refreshTokenId != value)
                {
                    _refreshTokenId = value;
                    _refreshTokenId_IsDirty = true;
                }
            }
        }

        public ListWithDirtyFlag<string> Scopes
        {
            get
            {
                return _scopes;
            }
        }

        public TokenStorageOptions TokenStorage
        {
            get
            {
                return _tokenStorage;
            }
        }

        public string ClientId
        {
            get
            {
                return _clientId;
            }
            set
            {
                if (_clientId != value)
                {
                    _clientId = value;
                    _clientId_IsDirty = true;
                }
            }
        }

        public string AccountId
        {
            get
            {
                return _accountId;
            }
            set
            {
                if (_accountId != value)
                {
                    _accountId = value;
                    _accountId_IsDirty = true;
                }
            }
        }

        public string UserId
        {
            get
            {
                return _userId;
            }
            set
            {
                if (_userId != value)
                {
                    _userId = value;
                    _userId_IsDirty = true;
                }
            }
        }

        public Int64? TimeCreatedInUnixMicroseconds
        {
            get
            {
                return _timeCreatedInUnixMicroseconds;
            }
        }

        public Int64? TimeUpdatedInUnixMicroseconds
        {
            get
            {
                return _timeUpdatedInUnixMicroseconds;
            }
        }
    }
}

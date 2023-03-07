# .NET Core 6 Web API & Entity Framework Core & JWT

## This project utilizes a connection to an SQL database and implements authentication and identification through the use of the JWT package.

## To utilize this web API, it is necessary to install the following packages.

### Authentication and Identification

  - Microsoft.IdentityModel.JsonWebTokens
  - System.IdentityModel.Tokens.Jwt

### Connection to an SQL database

  - Microsoft.EntityFrameworkCore.Proxies
  - Microsoft.EntityFrameworkCore.SqlServer
  - Microsoft.EntityFrameworkCore.Tools

If you intend to use JWT for your web application, kindly refer to the following code. Please note that this code obtains the token from the header, whereas you may need to obtain the token from a cookie. 

```
services
            .AddAuthentication(options =>
            {
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(cfg =>
            {
                cfg.RequireHttpsMetadata = false;
                cfg.SaveToken = true;

                cfg.TokenValidationParameters = new TokenValidationParameters
                {
                    ClockSkew = TimeSpan.Zero,
                    RequireSignedTokens = true,

                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(signingKey)),

                    RequireExpirationTime = false,
                    ValidateLifetime = false,

                    ValidateAudience = true,
                    ValidAudience = Configuration["BearerTokens:Audience"],

                    ValidateIssuer = true,
                    ValidIssuer = Configuration["BearerTokens:Issuer"],

                    TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(encryptionKey))
                };

                cfg.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        if (context.Request.Cookies.ContainsKey("_wcauth"))
                        {
                            context.Token = context.Request.Cookies["_wcauth"];
                        }

                        return Task.CompletedTask;
                    },

                    OnChallenge = x =>
                    {
                        if (x.AuthenticateFailure?.Message == "TokenValidationFailed")
                        {
                            x.Response.Cookies.Delete("_wcauth", new CookieOptions
                            {
                                Domain = x.Request.HttpContext.ExtractDomain(),
                                HttpOnly = true,
                                Path = "/",
                            });

                            x.HandleResponse();
                        }

                        return Task.CompletedTask;
                    },

                    OnTokenValidated = async context =>
                    {
                        var claimsIdentity = context.Principal?.Identity as ClaimsIdentity;
                        if (claimsIdentity?.Claims == null || !claimsIdentity.Claims.Any())
                        {
                            context.Fail("TokenValidationFailed");
                            return;
                        }

                        var userIdString = claimsIdentity.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                        if (!int.TryParse(userIdString, out var userId))
                        {
                            context.Fail("TokenValidationFailed");
                            return;
                        }

                        var securityService = context.HttpContext.RequestServices.GetRequiredService<ISecurityService>();
                        var userInfo = await securityService.GetUserInfo(userId);

                        var securityStamp = claimsIdentity.FindFirst(ClaimTypes.SerialNumber)?.Value;
                        if (securityStamp != null && userInfo.SecurityStamp != securityStamp)
                        {
                            context.Fail("TokenValidationFailed");
                            return;
                        }

                        if (context.SecurityToken is not JwtSecurityToken accessToken || string.IsNullOrWhiteSpace(accessToken.RawData))
                        {
                            context.Fail("TokenValidationFailed");
                        }
                    }
                };
            });

```


### Use this code at user login

```
Response.Cookies.Append("_wcauth", accessToken, new CookieOptions
        {
            Domain = Request.HttpContext.ExtractDomain(),
            HttpOnly = true,
            Path = "/",
            Expires = DateTime.Now.AddYears(1)
        });
        
```

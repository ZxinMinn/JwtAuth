using JwtAuth.Manager;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuth.Model
{
    public class JwtService : IAuthService
    {
        public string SecretKey { get ; set; }
        public JwtService(string secretKey)
        {
            SecretKey = secretKey;
        }
        public string GenerateToken(IAuthContainerModel authContainerModel)
        {
            if (authContainerModel == null || authContainerModel.Claims==null || authContainerModel.Claims.Length == 0)
            {
                throw new ArgumentException("Argument Exception");
            }
            else
            {
                SecurityTokenDescriptor securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = new ClaimsIdentity(authContainerModel.Claims),
                    Expires = DateTime.UtcNow.AddMinutes(authContainerModel.ExpiredMinute),
                    SigningCredentials = new SigningCredentials(GetSymmetricSecurityKey(), authContainerModel.SecurityAlgorithm)
                };
                JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                SecurityToken securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
                string token = jwtSecurityTokenHandler.WriteToken(securityToken);
                return token;
            }
        }

        public IEnumerable<Claim> GetTokenClaims(string token)
        {
            ClaimsPrincipal claimsPrincipal=new ClaimsPrincipal();
            if (!string.IsNullOrEmpty(token))
            {
                try
                {
                    TokenValidationParameters tokenValidationParameters = GetTokenValidationParameters();
                    JwtSecurityTokenHandler jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                    claimsPrincipal = jwtSecurityTokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
                }
                catch(Exception ex)
                {

                }         
            }
            return claimsPrincipal.Claims;
        }

        public bool IsValidToken(string token)
        {
            bool isValid = false;
            if (!string.IsNullOrEmpty(token))
            {
                TokenValidationParameters validationParameters = GetTokenValidationParameters();
                JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();
                try
                {
                    ClaimsPrincipal principal = tokenHandler.ValidateToken(token, validationParameters, out SecurityToken validateToken);
                    isValid = principal.Identity.IsAuthenticated;
                }catch(Exception ex)
                {
   
                    isValid= false;
                }
            }
            return isValid;
        }
        private SecurityKey GetSymmetricSecurityKey()
        {
            byte[] symmetricKey = Convert.FromBase64String(SecretKey);
            return new SymmetricSecurityKey(symmetricKey);
        }
        private TokenValidationParameters GetTokenValidationParameters()
        {
            return new TokenValidationParameters()
            {
                ValidateIssuer = false,
                ValidateAudience = false,
                IssuerSigningKey = GetSymmetricSecurityKey()
            };
        }
      
    }
}

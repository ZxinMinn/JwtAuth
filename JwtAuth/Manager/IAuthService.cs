using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuth.Manager
{
    public interface IAuthService
    {
        string SecretKey { get; set; }
        bool IsValidToken(string token);
        string GenerateToken(IAuthContainerModel authContainerModel);
        IEnumerable<Claim> GetTokenClaims(string token);
    }
}

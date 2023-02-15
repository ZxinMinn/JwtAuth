using JwtAuth.Manager;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuth.Model
{
    public class JwtContainerModel : IAuthContainerModel
    {
        public string SecretKey { get; set; } = "VGhpcyBJcyBUaGUgU2VjdXJpdHkgS2V5IEZvciBKV1QgVG9rZW4gVmFsaWRhdGlvbiBQYXJhbWV0ZXJz";
        public string SecurityAlgorithm { get; set; } = SecurityAlgorithms.HmacSha256Signature;
        public int ExpiredMinute { get; set; } = 10080;
        public Claim[] Claims { get ; set; }
      
    }   

}

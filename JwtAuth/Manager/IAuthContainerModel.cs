using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuth.Manager
{
    public interface IAuthContainerModel
    {
         string SecretKey { get; set; }
        string SecurityAlgorithm { get; set; }
        int ExpiredMinute { get; set; }
        Claim [] Claims { get; set; }
    }

}

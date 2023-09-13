using System;
namespace JwtWebApiTutorial
{
	public class User
	{
		public string? UserName { get; set; }

		public byte[] PasswordHash { get; set; }

		public byte[] passwordSalt { get; set; }

	}
}


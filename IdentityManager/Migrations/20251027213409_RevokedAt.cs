using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace IdentityManager.Migrations
{
    /// <inheritdoc />
    public partial class RevokedAt : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "Revoked",
                table: "RefreshTokens",
                newName: "RevokedAt");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.RenameColumn(
                name: "RevokedAt",
                table: "RefreshTokens",
                newName: "Revoked");
        }
    }
}

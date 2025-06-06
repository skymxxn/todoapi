﻿using Todo.Api.Dtos.Common;
using Todo.Api.Dtos.Token;
using Todo.Api.Entities;

namespace Todo.Api.Services.Interfaces;

public interface ITokenService
{
    public string CreateEmailVerificationToken(User user);
    public Task<ResultDto<bool>> ValidateEmailVerificationTokenAsync(string token);
    public string CreateEmailChangeToken(User user);
    public Task<ResultDto<bool>> ValidateEmailChangeTokenAsync(string token);
    public string CreatePasswordResetToken(User user);
    public Task<ResultDto<bool>> ValidatePasswordResetTokenAsync(string token);
    public Task<TokenResponseDto> CreateTokenResponse(User user);
    public Task<ResultDto<TokenResponseDto>> RefreshTokensAsync(RefreshTokenRequestDto request);
}
import { Controller, Get, Post, Body, HttpCode, HttpStatus, UseGuards, Param, Query } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthSignUpDto, AuthSignInDto } from './dto';
import { Tokens } from './types';
import { AuthGuard } from '@nestjs/passport';
import { AtGuard, RtGuard } from 'src/common/guards';
import { GetCurrentUser, GetCurrentUserId, Public } from 'src/common/decorators';
import { ApiBearerAuth, ApiBody, ApiParam, ApiQuery, ApiTags } from '@nestjs/swagger';
import { NotFoundException } from './exceptions';
import { UserRole } from '@prisma/client';

@Controller('auth')
@ApiBearerAuth()
@ApiTags('auth')
export class AuthController {

    constructor(private authService: AuthService) {}

    @Public()
    @Post('/signup')
    @HttpCode(HttpStatus.CREATED)
    @ApiBody({ type: AuthSignUpDto })
    signup(@Body() dto: AuthSignUpDto): Promise<Tokens> {
        return this.authService.signupLocal(dto);
    }

    @Public()
    @Post('/signin')
    @ApiBody({ type: AuthSignInDto })
    @HttpCode(HttpStatus.OK)
    signin(@Body() dto: AuthSignInDto): Promise<Tokens> {
        return this.authService.signinLocal(dto);
    }

    @Post('/logout')
    @HttpCode(HttpStatus.OK)
    logout(@GetCurrentUserId() userId: number) {
        return this.authService.logout(userId);
    }

    @Public()
    @UseGuards(RtGuard) // check later
    @Post('/refresh')
    @HttpCode(HttpStatus.OK)
    refreshTokens(@GetCurrentUserId() userId: number, @GetCurrentUser('refreshToken') refreshToken: string) { 
        return this.authService.refreshTokens(userId, refreshToken);
    }

    @UseGuards(AuthGuard('jwt'))
    @Get('profile')
    getProfile(@GetCurrentUserId() userId: number, @GetCurrentUser() user: any) {
        if (!user) {
            throw new NotFoundException('User not found');
        }

        return { id: userId, email: user.email, role: user.role, firstname: user.firstname, lastname: user.lastname };
    }
}

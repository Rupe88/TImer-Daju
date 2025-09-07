/* eslint-disable @typescript-eslint/no-unsafe-argument */
/* eslint-disable @typescript-eslint/no-unused-vars */
import { Controller, Get, Post, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { Body } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDTO } from './dto/login.dto';
import type { Response } from 'express';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuthGuard } from '@nestjs/passport';
import { UsersService } from 'src/users/users.service';
import { TwoFAService } from './two-fa.service';
import { User } from '../users/entities/user.entity';
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UsersService,
    private readonly twoFAService: TwoFAService,
  ) {}

  @Post('register')
  async register(@Body() dto: CreateUserDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  async login(
    @Body() dto: LoginDTO,
    @Res({ passthrough: true }) res: Response,
  ) {
    const { token, user } = await this.authService.login(dto);

    res.cookie('jwt', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 3600000,
    });

    return { user, token };
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  profile(@Req() req: import('express').Request) {
    return Promise.resolve(req?.user);
  }

  // ✅ Logout
  @Post('logout')
  logout(@Res({ passthrough: true }) res: Response) {
    res.clearCookie('jwt');
    return { message: 'Logged out successfully' };
  }

  //google login
  @Get('google')
  @UseGuards(AuthGuard('google'))
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async googleAuth(@Req() _req: any) {}

  //for callback
  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  async googleAuthCallback(
    @Req() req: any,
    @Res({ passthrough: true }) res: any,
  ): Promise<{ message: string; token: string }> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    const user = req.user; // User information from Google
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const token = await this.authService.socialLogin(user);

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    res.cookie('access_token', token, {
      httpOnly: true,
      sameSite: 'lax', // Use 'lax' for CSRF protection
      secure: process.env.NODE_ENV === 'production', // Set to true in production
      maxAge: 24 * 60 * 60 * 1000, // 1 day
      path: '/', // Cookie path
    });
    return { message: 'Google authentication successful', token };
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-member-access
    // return res.redirect('http://localhost:3000/dashboard'); // Redirect to your frontend or desired URL
  }

  //for github
  @Get('github')
  @UseGuards(AuthGuard('github'))
  async githubAuth(@Req() _req: any) {}

  @Get('github/callback')
  @UseGuards(AuthGuard('github'))
  async githubAuthCallback(
    @Req() req: any,
    @Res({ passthrough: true }) res: any,
  ): Promise<{ message: string; token: string }> {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    const user = req.user; // User information from Google
    const token = await this.authService.socialLogin(user);

    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    res.cookie('access_token', token, {
      httpOnly: true,
      sameSite: 'lax', // Use 'lax' for CSRF protection
      secure: process.env.NODE_ENV === 'production', // Set to true in production
      maxAge: 24 * 60 * 60 * 1000, // 1 day
      path: '/', // Cookie path
    });
    // eslint-disable-next-line @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-member-access
    return { message: 'GitHub login successful', token };
    // return res.redirect('http://localhost:3000/dashboard'); // Redirect to your frontend or desired URL
  }

  //for 2fa authentication
  //generate qr code and secret
  @UseGuards(AuthGuard('jwt'))
  @Post('2fa/generate')
  async generateTwoFactorAuthSecret(@Req() req: any) {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    const user = req.user;
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access
    const secret = this.twoFAService.generateSecret(user.email);
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    await this.userService.setTwoFASecret(user.id, secret.base32);
    if (!secret.otpauth_url) {
      throw new Error('OTP Auth URL is missing');
    }
    const qrCode = await this.twoFAService.generateQRCode(secret.otpauth_url);
    return { qrCode, secret: secret.base32 };
  }
}

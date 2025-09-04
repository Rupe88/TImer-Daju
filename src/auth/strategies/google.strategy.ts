/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, VerifyCallback } from 'passport-google-oauth20';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get<string>('GOOGLE_CLIENT_ID') || '',
      clientSecret: configService.get<string>('GOOGLE_CLIENT_SECRET') || '',
      callbackURL: configService.get<string>('GOOGLE_CALLBACK_URL') || '',
      scope: ['email', 'profile'],
      passReqToCallback: false, // 👈 fixes the type issue
    });
  }

  validate(
    accessToken: string,
    refreshToken: string,
    profile: any,
    done: VerifyCallback,
  ): any {
    const { displayName, emails } = profile;
    const user = {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      email: emails?.[0]?.value,
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      firstName: displayName?.split(' ')[0] || '',
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      lastName: displayName?.split(' ')[1] || '',
      provider: 'google',
    };
    done(null, user);
  }
}

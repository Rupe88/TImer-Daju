import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { PassportModule } from '@nestjs/passport';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './strategies/jwt.strategy';
import { GithubStrategy } from './strategies/github.strategy';
import { GoogleStrategy } from './strategies/google.strategy';
import { TwoFAService } from './two-fa.service';
import { UsersModule } from 'src/users/users.module';

@Module({
  imports: [
    UsersModule,
    // TypeORM feature for User entity
    TypeOrmModule.forFeature([User]),

    // Passport module for JWT authentication
    PassportModule.register({
      defaultStrategy: 'jwt',
    }),

    // JWT module with async configuration from ConfigService
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    GithubStrategy,
    GoogleStrategy,
    TwoFAService,
  ],
  exports: [AuthService],
})
export class AuthModule {}

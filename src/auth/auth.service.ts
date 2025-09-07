import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcryptjs';
import { CreateUserDto } from './dto/create-user.dto';
import { LoginDTO } from './dto/login.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepo: Repository<User>,
    private readonly jwtService: JwtService,
  ) {}

  //for register

  async register(dto: CreateUserDto): Promise<User> {
    const existing = await this.usersRepo.findOne({
      where: { email: dto.email },
    });
    if (existing) {
      throw new UnauthorizedException('User already exists');
    }

    const hashedPassword = await bcrypt.hash(dto.password, 10);
    const user = this.usersRepo.create({
      ...dto,
      password: hashedPassword,
    });
    return this.usersRepo.save(user);
  }

  //for login user
  async login(dto: LoginDTO): Promise<{ token: string; user: Partial<User> }> {
    const user = await this.usersRepo.findOne({ where: { email: dto.email } });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const isValid = await bcrypt.compare(dto.password, user.password);
    if (!isValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    const payload = { id: user.id, email: user.email };
    const token = this.jwtService.sign(payload);

    return {
      token,
      user: {
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
      },
    };
  }

  // 🔹 Social Login (Google/GitHub)
  async socialLogin(userData: {
    email: string;
    firstName: string;
    lastName?: string;
    provider: string;
  }) {
    // check if user already exists
    let user = await this.usersRepo.findOne({
      where: { email: userData.email },
    });

    if (!user) {
      // create a new user without password
      user = this.usersRepo.create({
        email: userData.email,
        firstName: userData.firstName,
        lastName: userData.lastName ?? '',
        password: '', // empty password for social accounts
        provider: userData.provider,
      });
      await this.usersRepo.save(user);
    }

    // sign JWT
    const payload = { id: user.id, email: user.email };
    const token = this.jwtService.sign(payload);

    return token;
  }

  // ✅ This method is called by JwtStrategy
  async validateUser(payload: { id: number; email: string }): Promise<User> {
    const user = await this.usersRepo.findOne({ where: { id: payload.id } });
    if (!user) throw new UnauthorizedException('User not found');
    return user;
  }

  generateJwtToken(payload: { id: number; email: string }): string {
    return this.jwtService.sign(payload);
  }
}

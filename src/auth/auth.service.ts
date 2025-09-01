import { Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from 'src/users/entities/user.entity';
import { Repository } from 'typeorm';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(User)
    private readonly usersRepo: Repository<User>,
  ) {}

  // ✅ This method is called by JwtStrategy
  async validateUser(payload: { id: number; email: string }): Promise<User> {
    const user = await this.usersRepo.findOne({ where: { id: payload.id } });
    if (!user) throw new UnauthorizedException('User not found');
    return user;
  }
}

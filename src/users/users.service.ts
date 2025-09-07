import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private readonly userRepository: Repository<User>,
  ) {}

  //find user by email

  async findUserByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  //set two factor authentication secret

  async setTwoFASecret(id: number, secret: string) {
    return this.userRepository.update(id, { twoFactorSecret: secret });
  }

  //enable two factor authentication
  async enableTwoFA(id: number) {
    return this.userRepository.update(id, { isTwoFAEnabled: true });
  }

  // find user by id

  async findUserById(id: number): Promise<User | null> {
    return this.userRepository.findOne({ where: { id } });
  }
}

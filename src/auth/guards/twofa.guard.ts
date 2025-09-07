import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';

@Injectable()
export class TwoFaGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const request = context.switchToHttp().getRequest();

    //pending_user cookie should be present
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    const pendingUser = request.cookies['pending_user'];

    if (pendingUser) {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment
      request.user = { id: pendingUser, isTwoFAEnabled: true }; // Attach user info to request object
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    if (!request.user) {
      throw new UnauthorizedException('No user found');
    }
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    if (!request.user.isTwoFAEnabled) {
      throw new UnauthorizedException('2FA is not enabled for this user');
    }
    return true;
  }
}

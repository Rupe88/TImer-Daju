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

    // Check for pending_user cookie
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-member-access
    const pendingUser = request.cookies['pending_user'];

    if (!pendingUser) {
      throw new UnauthorizedException(
        'No pending 2FA session found. Please login first.',
      );
    }

    // Attach user info to request object
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    request.user = {
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      id: pendingUser,
      isTwoFAEnabled: true,
    };

    return true;
  }
}

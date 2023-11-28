import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { AuthController } from './auth.controller';
import { UserSchema } from './entity/auth.entity';
import { AuthService } from './service/auth.service';
import { JwtService } from './service/jwt.service';
import { JwtStrategy } from './strategy/jwt.strategy';
import { MongooseModule } from '@nestjs/mongoose';
import { RedisModule } from 'src/providers/redis.module';
import { SessionSchema } from './entity/session.entity';

@Module({
  imports: [
    JwtModule.register({
      secret: 'user-secret-key',
      signOptions: { expiresIn: '365d' },
    }),
    MongooseModule.forFeature([
      { name: 'Users', schema: UserSchema },
      { name: 'Sessions', schema: SessionSchema },
    ]),
    RedisModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtService, JwtStrategy],
})
export class AuthModule {}

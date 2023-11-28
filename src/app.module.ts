import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    MongooseModule.forRootAsync({
      useFactory: () => ({
        uri: process.env.USER_DB,
      }),
    }),
    AuthModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}

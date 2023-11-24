import { Body, Controller, HttpStatus, Inject } from '@nestjs/common';
import { GrpcMethod } from '@nestjs/microservices';
import {
  ChangePasswordRequestDto,
  ForgetPasswordDto,
  LoginRequestDto,
  LogoutRequestDto,
  RegisterRequestDto,
  ResetPasswordDto,
  UpdateRequestDto,
  ValidateRequestDto,
} from './auth.dto';
import {
  AUTH_SERVICE_NAME,
  RegisterResponse,
  LoginResponse,
  ValidateResponse,
  LogoutResponse,
  LogoutRequest,
  UpdateRequest,
  UpdateResponse,
  ChangePasswordRequest,
  ChangePasswordResponse,
  ResetPasswordRequest,
  ForgetPasswordResponse,
  AddWalletAmountRequest,
  AddWalletAmountResponse,
  CheckWalletRequest,
  CheckWalletResponse,
  TransferMoneyRequest,
  TransferMoneyResponse,
  RegisterRequest,
} from './auth.pb';
import { AuthService } from './service/auth.service';

@Controller()
export class AuthController {
  @Inject(AuthService)
  private readonly service: AuthService;

  @GrpcMethod(AUTH_SERVICE_NAME, 'Register')
  private register(
    registerRequest: RegisterRequest,
  ): Promise<RegisterResponse> {
    return this.service.register(registerRequest);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Login')
  private login(payload: LoginRequestDto): Promise<LoginResponse> {
    return this.service.login(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'Validate')
  private validate(payload: ValidateRequestDto): Promise<ValidateResponse> {
    return this.service.validate(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'update')
  private update(payload: UpdateRequestDto): Promise<UpdateResponse> {
    return this.service.update(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'forgetPassword')
  private forgetPassword(
    payload: ForgetPasswordDto,
  ): Promise<ForgetPasswordResponse> {
    return this.service.forgetPassword(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'resetPassword')
  private resetPassword(payload: ResetPasswordDto) {
    return this.service.resetPassword(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'changePassword')
  private changePassword(
    payload: ChangePasswordRequestDto,
  ): Promise<ChangePasswordResponse> {
    return this.service.changePassword({ ...payload, userId: payload.userId });
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'logout')
  private logout(payload: any): Promise<LogoutResponse> {
    return this.service.logout(payload.userId);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'addWalletAmount')
  private addWalletAmount(
    payload: AddWalletAmountRequest,
  ): Promise<AddWalletAmountResponse> {
    return this.service.addWalletAmount(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'checkWallet')
  private checkWallet(
    payload: CheckWalletRequest,
  ): Promise<CheckWalletResponse> {
    return this.service.checkWallet(payload);
  }

  @GrpcMethod(AUTH_SERVICE_NAME, 'moneyTransaction')
  private moneyTransaction(
    payload: TransferMoneyRequest,
  ): Promise<TransferMoneyResponse> {
    return this.service.moneyTransaction(payload);
  }
}

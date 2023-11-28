import {
  IsEmail,
  IsNotEmpty,
  IsNumberString,
  IsOptional,
  IsString,
  Length,
  Matches,
} from 'class-validator';
import {
  ChangePasswordRequest,
  ForgetPasswordRequest,
  LoginRequest,
  LogoutRequest,
  RegisterRequest,
  ResetPasswordRequest,
  UpdateRequest,
  ValidateRequest,
} from './auth.pb';
import { ApiProperty } from '@nestjs/swagger';

export class LoginRequestDto implements LoginRequest {
  @IsEmail()
  @IsNotEmpty()
  @ApiProperty()
  public readonly email: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  public readonly password: string;
}

export class RegisterRequestDto implements RegisterRequest {
  @IsNotEmpty()
  @IsString()
  firstName: string;

  @IsNotEmpty()
  @IsString()
  lastName: string;

  @IsString()
  @Length(5, 20)
  @IsNotEmpty()
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message:
      'Username must be at least 5 characters long and contain only letters, numbers, and underscores',
  })
  userName: string;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  @Length(6, 20)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
    {
      message:
        'Password must be at least 6 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
    },
  )
  password: string;

  @IsNotEmpty()
  @Length(10, 10, {
    message: 'Invalid contact number format. It should be 10 digit long ',
  })
  @IsNumberString(
    { no_symbols: true },
    { message: 'Contact number can only contain numbers' },
  )
  contactNumber: string;

  @IsNotEmpty()
  @IsString()
  address: string;
}

export class ValidateRequestDto implements ValidateRequest {
  @IsString()
  public readonly token: string;
}

export class LogoutRequestDto implements LogoutRequest {
  @IsString()
  public readonly userId: string;
}

export class UpdateRequestDto implements UpdateRequest {
  @IsString()
  @IsOptional()
  firstName: string;

  @IsString()
  @IsOptional()
  lastName: string;

  @IsString()
  @IsOptional()
  @Length(5, 20)
  @Matches(/^[a-zA-Z0-9_]+$/, {
    message:
      'Username must be at least 5 characters long and contain only letters, numbers, and underscores',
  })
  userName: string;

  @IsString()
  @IsOptional()
  @IsEmail()
  email: string;

  @IsString()
  @IsOptional()
  @Length(6, 20)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
    {
      message:
        'Password must be at least 6 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
    },
  )
  password: string;

  @IsString()
  @IsOptional()
  @Length(10, 10, {
    message: 'Invalid contact number format. It should be 10 digit long ',
  })
  @IsNumberString(
    { no_symbols: true },
    { message: 'Contact number can only contain numbers' },
  )
  contactNumber: string;

  @IsString()
  @IsOptional()
  address: string;

  userId: string;
}

export class ChangePasswordRequestDto implements ChangePasswordRequest {
  @IsString()
  oldPassword: string;

  @IsString()
  @Length(6, 20)
  @Matches(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
    {
      message:
        'Password must be at least 6 characters long and contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
    },
  )
  newPassword: string;

  @IsString()
  userId: string;
}

export class ForgetPasswordDto implements ForgetPasswordRequest {
  @IsEmail()
  email: string;
}

export class ResetPasswordDto implements ResetPasswordRequest {
  @IsString()
  otp: string;

  @IsEmail()
  email: string;

  @IsString()
  password: string;
}

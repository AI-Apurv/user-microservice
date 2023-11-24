import {
  HttpStatus,
  Inject,
  Injectable,
  InternalServerErrorException,
  Session,
} from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { JwtService } from './jwt.service';
import {
  RegisterRequestDto,
  LoginRequestDto,
  ValidateRequestDto,
  UpdateRequestDto,
  ForgetPasswordDto,
  ResetPasswordDto,
  ChangePasswordRequestDto,
} from '../auth.dto';
import { Users } from '../entity/auth.entity';
import {
  AddWalletAmountRequest,
  AddWalletAmountResponse,
  ChangePasswordRequest,
  ChangePasswordResponse,
  CheckWalletRequest,
  CheckWalletResponse,
  ForgetPasswordResponse,
  LoginResponse,
  LogoutResponse,
  RegisterResponse,
  ResetPasswordRequest,
  ResetPasswordResponse,
  TransferMoneyRequest,
  TransferMoneyResponse,
  UpdateResponse,
  ValidateResponse,
} from '../auth.pb';
import { RedisService } from 'src/providers/redis.service';
import { Sessions } from '../entity/session.entity';
import * as nodemailer from 'nodemailer';
import * as bcrypt from 'bcrypt';
import { userResponse } from 'src/common/user.response';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(Users.name)
    private readonly userModel: Model<Users>,
    @InjectModel(Sessions.name)
    private readonly sessionModel: Model<Sessions>,
    private readonly jwtService: JwtService,
    private readonly redisService: RedisService,
  ) {}

  public async register(
    registerRequestDto: RegisterRequestDto,
  ): Promise<RegisterResponse> {
    let user: Users = await this.userModel.findOne({
      email: registerRequestDto.email,
    });
    if (user) {
      return {
        status: HttpStatus.CONFLICT,
        response: userResponse.ALREADY_EXISTS,
        error: null,
      };
    }
    const newUser = new this.userModel({
      firstName: registerRequestDto.firstName,
      lastName: registerRequestDto.lastName,
      userName: registerRequestDto.userName,
      email: registerRequestDto.email,
      password: await this.jwtService.encodePassword(
        registerRequestDto.password,
      ),
      contactNumber: registerRequestDto.contactNumber,
      address: registerRequestDto.address,
    });
    await newUser.save();
    return {
      status: HttpStatus.CREATED,
      response: userResponse.SIGNUP_SUCCESS,
      error: null,
    };
  }

  public async login(loginRequestDto: LoginRequestDto): Promise<LoginResponse> {
    const user: Users = await this.userModel.findOne({
      email: loginRequestDto.email,
    });
    if (!user) {
      return {
        status: HttpStatus.NOT_FOUND,
        response: userResponse.NOT_EXIST,
        token: null,
        error: null,
      };
    }
    await this.redisService.redisSet(user.email, true, 3600);
    const session = await this.sessionModel.findOne({ email: user.email });
    if (!session) {
      const status = new this.sessionModel({
        email: loginRequestDto.email,
        isActive: true,
      });
      await status.save();
    } else {
      session.isActive = true;
      await session.save();
    }
    const isPasswordValid = await this.jwtService.isPasswordValid(
      loginRequestDto.password,
      user.password,
    );
    if (!isPasswordValid) {
      return {
        status: HttpStatus.NOT_FOUND,
        response: userResponse.WRONG_PASS,
        error: null,
        token: null,
      };
    }
    const token: string = this.jwtService.generateToken(user);
    return {
      token,
      status: HttpStatus.OK,
      response: userResponse.LOGIN_SUCCESS,
      error: null,
    };
  }

  public async validate(
    validateRequestDto: ValidateRequestDto,
  ): Promise<ValidateResponse> {
    const decoded: Users = await this.jwtService.verify(
      validateRequestDto.token,
    );
    if (!decoded) {
      return {
        status: HttpStatus.FORBIDDEN,
        error: [userResponse.INVALID_TOKEN],
        userId: null,
        email: null,
      };
    }
    const user: Users = await this.jwtService.validateUser(decoded);
    if (!user)
      return {
        status: HttpStatus.CONFLICT,
        error: [userResponse.NOT_EXIST],
        userId: null,
        email: null,
      };
    const status = await this.redisService.redisGet(user.email);
    if (status === null) {
      const isActive = await this.sessionModel.findOne({ email: user.email });
      if (!isActive)
        return {
          status: HttpStatus.BAD_REQUEST,
          error: [userResponse.LOGOUT],
          userId: null,
          email: null,
        };
    }
    if (status === 'false')
      return {
        status: HttpStatus.BAD_REQUEST,
        error: [userResponse.LOGOUT],
        userId: null,
        email: null,
      };

    return {
      status: HttpStatus.OK,
      error: null,
      userId: user.id,
      email: user.email,
    };
  }

  public async logout(userId: string): Promise<LogoutResponse> {
    const user: Users = await this.userModel.findOne({ _id: userId });
    await this.redisService.redisSet(user.email, false, 7200);
    const session = await this.sessionModel.findOne({ email: user.email });
    session.isActive = false;
    session.save();
    return {
      status: HttpStatus.OK,
      response: userResponse.LOGOUT_SUCCESS,
      error: null,
    };
  }

  public async update(payload: UpdateRequestDto): Promise<UpdateResponse> {
    const data: Users = await this.userModel.findOne({ id: payload.userId });
    await this.userModel.findOneAndUpdate(
      { email: data.email },
      { $set: payload },
      { new: true },
    );
    return {
      status: HttpStatus.OK,
      response: userResponse.UPDATE_SUCCESS,
      error: null,
    };
  }

  public async forgetPassword(
    payload: ForgetPasswordDto,
  ): Promise<ForgetPasswordResponse> {
    const data: Users = await this.userModel.findOne({ email: payload.email });
    if (!data)
      return {
        status: HttpStatus.BAD_REQUEST,
        response: userResponse.NOT_EXIST,
        error: null,
      };
    const OTP = Math.floor(1000 + Math.random() * 9000);
    await this.redisService.redisSet(payload.email, OTP.toString(), 120);
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      host: 'smtp.gmail.com',
      port: 465,
      secure: true,
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASS,
      },
    });
    const mailOptions = {
      from: process.env.EMAIL,
      to: payload.email,
      subject: 'Password Reset Request',
      text: `Your OTP for password reset is: ${OTP}`,
    };
    transporter.sendMail(mailOptions, (error, info) => {
      if (error)
        throw new InternalServerErrorException(userResponse.EMAIL_FAIL);
      else console.log('Email sent: ' + info.response);
    });
    return { status: 200, error: null, response: userResponse.EMAIL_SUCCESS };
  }

  public async resetPassword(
    payload: ResetPasswordDto,
  ): Promise<ResetPasswordResponse> {
    let redisOTP = await this.redisService.redisGet(payload.email);
    if (redisOTP == payload.otp) {
      const hashedPassword = await bcrypt.hash(payload.password, 10);
      const user = await this.userModel.findOne({ email: payload.email });
      if (user) {
        await this.redisService.redisDel(payload.email);
        user.password = hashedPassword;
        await user.save();
        return {
          status: HttpStatus.OK,
          response: userResponse.PASS_RESET,
          error: null,
        };
      }
    } else {
      return {
        status: HttpStatus.BAD_REQUEST,
        response: userResponse.PASS_RESET_FAIL,
        error: null,
      };
    }
  }

  public async changePassword(
    payload: ChangePasswordRequestDto,
  ): Promise<ChangePasswordResponse> {
    const user = await this.userModel.findById(payload.userId);
    if (!user) {
      return {
        status: HttpStatus.NOT_FOUND,
        response: userResponse.NOT_EXIST,
        error: null,
      };
    }
    const isOldPassword = await this.jwtService.isPasswordValid(
      payload.oldPassword,
      user.password,
    );
    if (!isOldPassword) {
      return {
        status: HttpStatus.BAD_REQUEST,
        response: userResponse.WRONG_PASS,
        error: null,
      };
    }
    if (user.password === payload.newPassword)
      return {
        status: HttpStatus.BAD_REQUEST,
        response: userResponse.SAME_PASS,
        error: null,
      };

    user.password = await this.jwtService.encodePassword(payload.newPassword);
    await user.save();
    return {
      status: HttpStatus.OK,
      response: userResponse.PASS_CHANGE,
      error: null,
    };
  }

  public async addWalletAmount(
    payload: AddWalletAmountRequest,
  ): Promise<AddWalletAmountResponse> {
    const user = await this.userModel.findById(payload.userId);
    if (!user)
      return {
        status: HttpStatus.NOT_FOUND,
        response: userResponse.NOT_EXIST,
        error: null,
      };
    user.walletAmount += payload.amount;
    user.save();
    return {
      status: HttpStatus.OK,
      response: userResponse.AMOUNT_ADDED,
      error: null,
    };
  }

  public async checkWallet(
    payload: CheckWalletRequest,
  ): Promise<CheckWalletResponse> {
    const user = await this.userModel.findById(payload.userId);
    return { walletAmount: user.walletAmount };
  }

  public async moneyTransaction(
    payload: TransferMoneyRequest,
  ): Promise<TransferMoneyResponse> {
    const user = await this.userModel.findById(payload.userId);
    user.walletAmount -= payload.amount;
    user.save();
    const seller = await this.userModel.findById(payload.sellerId);
    seller.walletAmount += payload.amount;
    seller.save();
    return {
      status: HttpStatus.OK,
      response: userResponse.TRANSACTION_SUCCESS,
      error: null,
    };
  }
}

import { Controller, Logger } from '@nestjs/common';
import { EventPattern, MessagePattern, Payload } from '@nestjs/microservices';
import { AuthService } from './auth.service';
import { LoginUserDTO, RegisterUserDTO } from './dto';

@Controller()
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  private logger = new Logger('Auth controller')

  @MessagePattern('auth.register.user')
  registerUser(@Payload() registerUserDTO: RegisterUserDTO) {
    this.logger.log('auth.register.user', registerUserDTO)
    return this.authService.register(registerUserDTO)
  }

  @MessagePattern('auth.login.user')
  loginUser(@Payload() loginUserDTO: LoginUserDTO) {
    this.logger.log('auth.login.user', loginUserDTO)
    return this.authService.login(loginUserDTO)
  }

  @MessagePattern('auth.verify.user')
  verifyToken(@Payload() token: string) {
    const data = this.authService.verifyToken(token)
    this.logger.log(data)
    return data
  }
}

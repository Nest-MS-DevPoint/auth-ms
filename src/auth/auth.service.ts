import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoginUserDTO, RegisterUserDTO } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interface/jwt-payload.interface';
import { envs } from 'src/config';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {

    constructor(
        private jwtService: JwtService
    ) {
        super();
    }

    private readonly logger = new Logger('AuthService')
    async onModuleInit() {
        await this.$connect();
        this.logger.log('Mongo Database connected!')
    }

    async signIn(payload: JwtPayload) {
        return this.jwtService.sign(payload)
    }


    async register(registerUserDTO: RegisterUserDTO) {

        const { name, email, password } = registerUserDTO;
        try {

            const user = await this.user.findUnique({
                where: {
                    email: email
                }
            });

            if (user) {
                throw new RpcException({
                    status: 400,
                    message: 'User already exists!'
                })
            }

            const newUser = await this.user.create({
                data: {
                    name: name,
                    email: email,
                    password: bcrypt.hashSync(password, 10)
                }
            })

            const { password: _, ...rest } = newUser

            return {
                user: rest,
                token: await this.signIn(rest)
            }

        } catch (error) {
            this.logger.error('Message error: ', error)
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }

    async login(loginUserDTO: LoginUserDTO) {

        const { email, password } = loginUserDTO;
        try {

            const user = await this.user.findUnique({
                where: { email }
            });

            if (!user) {
                throw new RpcException({
                    status: 400,
                    message: 'Invalid credentials!'
                })
            }

            const isPasswordValid = bcrypt.compareSync(password, user.password)

            if (!isPasswordValid) {
                throw new RpcException({
                    status: 400,
                    message: 'Invalid credentials!'
                })
            }

            const { password: _, ...rest } = user

            return {
                user: rest,
                token: await this.signIn(rest)
            }

        } catch (error) {
            throw new RpcException({
                status: 400,
                message: error.message
            })
        }
    }

    async verifyToken(token: string) {
        this.logger.log('token=============', token)
        try {

            const { sub, iat, exp, ...user } = this.jwtService.verify(token, {
                secret: envs.jwtSecret
            })

            console.log('user------------', user)

            return {
                user,
                token: await this.signIn(user)
            }

        } catch (error) {
            this.logger.debug(error)
            throw new RpcException({
                status: 401,
                message: 'Invalid token'
            })
        }
    }

}

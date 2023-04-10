import { IsJSON, IsOptional, IsString } from 'class-validator';

export class MetamaskInput {
    @IsString()
    password: string;

    json: {
        iv: string;
        data: string;
        salt: string;
    };
}

export class MetamaskOutput {
    @IsJSON()
    @IsOptional()
    addresses: string;
}

/* 
export class SignInData
    implements Required<MetamaskInput>
{
    @IsString()
    password: string;

    @IsJSON()
    json:string;
} */

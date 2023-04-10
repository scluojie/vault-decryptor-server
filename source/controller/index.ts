import { createAPI } from 'koagger';

import { isProduct } from '../model';
import { UserController } from './User';
import { MetamaskController } from './Metamask';

export * from './User';

export const { swagger, mocker, router } = createAPI({
    mock: !isProduct,
    controllers: [UserController, MetamaskController]
});

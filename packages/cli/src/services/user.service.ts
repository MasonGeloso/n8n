import { Service } from 'typedi';
import type { EntityManager, FindManyOptions, FindOneOptions, FindOptionsWhere } from 'typeorm';
import { In } from 'typeorm';
import { User } from '@db/entities/User';
import type { IUserSettings } from 'n8n-workflow';
import { UserRepository } from '@/databases/repositories';
import { getInstanceBaseUrl } from '@/UserManagement/UserManagementHelper';
import type { PublicUser } from '@/Interfaces';
import type { PostHogClient } from '@/posthog';
import { JwtService } from '@/services/jwt.service';
import { BadRequestError } from '@/ResponseHelper';
import type { Role } from '@/databases/entities/Role';
import { UserManagementMailer } from '@/UserManagement/email';

@Service()
export class UserService {
	constructor(
		private readonly jwtService: JwtService,
		private readonly userRepository: UserRepository,
		private readonly mailer: UserManagementMailer,
	) {}

	async findOne(options: FindOneOptions<User>) {
		return this.userRepository.findOne({ relations: ['globalRole'], ...options });
	}

	async findOneOrFail(options: FindOneOptions<User>) {
		return this.userRepository.findOneOrFail({ relations: ['globalRole'], ...options });
	}

	async findMany(options: FindManyOptions<User>) {
		return this.userRepository.find(options);
	}

	async findOneBy(options: FindOptionsWhere<User>) {
		return this.userRepository.findOneBy(options);
	}

	create(data: Partial<User>) {
		return this.userRepository.create(data);
	}

	async save(user: Partial<User>) {
		return this.userRepository.save(user);
	}

	async update(userId: string, data: Partial<User>) {
		return this.userRepository.update(userId, data);
	}

	async getByIds(transaction: EntityManager, ids: string[]) {
		return transaction.find(User, { where: { id: In(ids) } });
	}

	getManager() {
		return this.userRepository.manager;
	}

	async updateSettings(userId: string, newSettings: Partial<IUserSettings>) {
		const { settings } = await this.userRepository.findOneOrFail({ where: { id: userId } });

		return this.userRepository.update(userId, { settings: { ...settings, ...newSettings } });
	}

	generatePasswordResetUrl(user: User) {
		const url = new URL(`${getInstanceBaseUrl()}/change-password`);
		const token = this.jwtService.signData({ sub: user.id }, { expiresIn: '1d' });
		url.searchParams.append('token', token);
		url.searchParams.append('mfaEnabled', user.mfaEnabled.toString());
		return url.toString();
	}

	generateInvitationUrl(inviter: User, inviteeId: string) {
		const url = new URL(`${getInstanceBaseUrl()}/signup`);
		const token = this.jwtService.signData(
			{ inviterId: inviter.id, inviteeId },
			{ expiresIn: '7d' },
		);
		url.searchParams.append('token', token);
		return url.toString();
	}

	async inviteUser(inviter: User, email: string, globalRole: Role): Promise<boolean> {
		let user = await this.userRepository.findOneBy({ email });
		if (user?.password) return true;
		if (!user) {
			user = await this.userRepository.save(this.create({ email, globalRole }));
		}
		const inviteAcceptUrl = this.generateInvitationUrl(inviter, user.id);
		const result = await this.mailer.invite({
			email,
			inviteAcceptUrl,
		});
		return result.emailSent;
	}

	async validateInvitationToken(token: string) {
		const { inviterId, inviteeId } = this.jwtService.verifyToken<{
			inviterId: string;
			inviteeId: string;
		}>(token);

		const users = await this.findMany({
			where: { id: In([inviterId, inviteeId]) },
		});
		if (users.length !== 2) {
			throw new BadRequestError('Invalid invitation token');
		}

		const invitee = users.find((user) => user.id === inviteeId);
		if (!invitee || invitee.password) {
			throw new BadRequestError('The invitation was likely either deleted or already claimed');
		}

		const inviter = users.find((user) => user.id === inviterId);
		return { invitee, inviter };
	}

	async toPublic(user: User, options?: { posthog?: PostHogClient }) {
		const { password, updatedAt, apiKey, authIdentities, ...rest } = user;

		const ldapIdentity = authIdentities?.find((i) => i.providerType === 'ldap');

		let publicUser: PublicUser = {
			...rest,
			signInType: ldapIdentity ? 'ldap' : 'email',
			hasRecoveryCodesLeft: !!user.mfaRecoveryCodes?.length,
		};

		if (options?.posthog) {
			publicUser = await this.addFeatureFlags(publicUser, options.posthog);
		}

		return publicUser;
	}

	private async addFeatureFlags(publicUser: PublicUser, posthog: PostHogClient) {
		// native PostHog implementation has default 10s timeout and 3 retries.. which cannot be updated without affecting other functionality
		// https://github.com/PostHog/posthog-js-lite/blob/a182de80a433fb0ffa6859c10fb28084d0f825c2/posthog-core/src/index.ts#L67
		const timeoutPromise = new Promise<PublicUser>((resolve) => {
			setTimeout(() => {
				resolve(publicUser);
			}, 1500);
		});

		const fetchPromise = new Promise<PublicUser>(async (resolve) => {
			publicUser.featureFlags = await posthog.getFeatureFlags(publicUser);
			resolve(publicUser);
		});

		return Promise.race([fetchPromise, timeoutPromise]);
	}
}

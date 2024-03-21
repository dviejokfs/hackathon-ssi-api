import { IStateManager, StateType } from "@sphereon/oid4vci-common";
import { LessThan, Repository } from "typeorm";
import { StateItem } from "./models";

export class PostgresStates<T extends StateType> implements IStateManager<T> {
    private readonly expiresInMS: number
    private readonly states: Map<string, T>
    private cleanupIntervalId?: NodeJS.Timer
    private readonly itemRepository: Repository<StateItem>;

    constructor(itemRepository: Repository<StateItem>, opts?: { expiresInSec?: number }) {
        this.itemRepository = itemRepository
        this.expiresInMS = opts?.expiresInSec !== undefined ? opts?.expiresInSec * 1000 : 180000
        this.states = new Map()
    }

    async set(id: string, dataValue: T): Promise<void> {
        const item = new StateItem();
        item.id = id;
        item.data = dataValue;
        item.expiresAt = new Date(Date.now() + this.expiresInMS);
        await this.itemRepository.save(item);
    }

    async get(id: string): Promise<T> {
        const item = await this.itemRepository.findOneBy({ id });
        if (!item) {
            throw new Error(`Item with id ${id} not found`);
        }
        return item.data;
    }

    async has(id: string): Promise<boolean> {
        const item = await this.itemRepository.findOneBy({ id });
        return !!item;
    }

    async delete(id: string): Promise<boolean> {
        const result = await this.itemRepository.delete(id);
        return result.affected > 0;
    }

    async clearExpired(timestamp?: number): Promise<void> {
        const now = timestamp ? new Date(timestamp) : new Date();
        await this.itemRepository.delete({ expiresAt: LessThan(now) });
    }

    async clearAll(): Promise<void> {
        await this.itemRepository.clear();
    }

    async getAsserted(id: string): Promise<T> {
        const item = await this.itemRepository.findOneOrFail({ where: { id } });
        return item.data;
    }

    async startCleanupRoutine(timeout?: number): Promise<void> {
        this.cleanupIntervalId = setInterval(() => {
            this.clearExpired();
        }, timeout ?? this.expiresInMS);
    }

    async stopCleanupRoutine(): Promise<void> {
        clearInterval(this.cleanupIntervalId as any);
    }
}
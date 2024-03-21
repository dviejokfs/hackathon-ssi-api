import { Column, CreateDateColumn, Entity, PrimaryColumn, UpdateDateColumn } from "typeorm";

@Entity()
export class StateItem {
    @PrimaryColumn()
    id: string;

    // data column json
    @Column("simple-json")
    data: any;

    @CreateDateColumn()
    createdAt: number;

    @UpdateDateColumn()
    updatedAt: number;

    @Column()
    expiresAt: Date;

}

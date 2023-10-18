#![cfg(feature = "test-sbf")]

mod program_test;
use {
    program_test::TestContext,
    solana_program_test::{processor, tokio, ProgramTest},
    solana_sdk::{
        account::Account as SolanaAccount, instruction::InstructionError, signature::Signer,
        signer::keypair::Keypair, transaction::TransactionError, transport::TransportError,
    },
    spl_pod::bytemuck::pod_from_bytes,
    spl_token_2022::{error::TokenError, extension::BaseStateWithExtensions, processor::Processor},
    spl_token_client::token::{ExtensionInitializationParams, TokenError as TokenClientError},
    spl_token_group_interface::{error::TokenGroupError, state::TokenGroupMember},
    std::sync::Arc,
};

fn setup_program_test() -> ProgramTest {
    let mut program_test = ProgramTest::default();
    program_test.add_program(
        "spl_token_2022",
        spl_token_2022::id(),
        processor!(Processor::process),
    );
    program_test
}

async fn setup(
    test_context: &mut TestContext,
    mint: Keypair,
    init_params: Vec<ExtensionInitializationParams>,
) {
    test_context
        .init_token_with_mint_keypair_and_freeze_authority(mint, init_params, None)
        .await
        .unwrap();
}

#[tokio::test]
async fn success_initialize_member() {
    let payer = Keypair::new();

    let group_authority = Keypair::new();
    let group_mint_keypair = Keypair::new();

    let member1_authority = Keypair::new();
    let member1_mint_keypair = Keypair::new();
    let member2_authority = Keypair::new();
    let member2_mint_keypair = Keypair::new();
    let member3_authority = Keypair::new();
    let member3_mint_keypair = Keypair::new();

    let program_test = setup_program_test();
    let mut context = program_test.start_with_context().await;
    context.set_account(
        &payer.pubkey(),
        &SolanaAccount {
            lamports: 500_000_000,
            ..SolanaAccount::default()
        }
        .into(),
    );
    let context = Arc::new(tokio::sync::Mutex::new(context));

    let create_context = || TestContext {
        context: context.clone(),
        token_context: None,
    };

    let mut group_test_context = create_context();
    setup(
        &mut group_test_context,
        group_mint_keypair.insecure_clone(),
        vec![ExtensionInitializationParams::GroupPointer {
            authority: Some(group_authority.pubkey()),
            group_address: Some(group_mint_keypair.pubkey()),
        }],
    )
    .await;
    let group_token_context = group_test_context.token_context.take().unwrap();

    group_token_context
        .token
        .token_group_initialize_with_rent_transfer(
            &payer.pubkey(),
            &group_token_context.mint_authority.pubkey(),
            &group_authority.pubkey(),
            5,
            &[&payer, &group_token_context.mint_authority],
        )
        .await
        .unwrap();

    let mut member1_test_context = create_context();
    setup(
        &mut member1_test_context,
        member1_mint_keypair.insecure_clone(),
        vec![ExtensionInitializationParams::GroupMemberPointer {
            authority: Some(member1_authority.pubkey()),
            member_address: Some(member1_mint_keypair.pubkey()),
        }],
    )
    .await;
    let member1_token_context = member1_test_context.token_context.take().unwrap();

    let mut member2_test_context = create_context();
    setup(
        &mut member2_test_context,
        member2_mint_keypair.insecure_clone(),
        vec![ExtensionInitializationParams::GroupMemberPointer {
            authority: Some(member2_authority.pubkey()),
            member_address: Some(member2_mint_keypair.pubkey()),
        }],
    )
    .await;
    let member2_token_context = member2_test_context.token_context.take().unwrap();

    let mut member3_test_context = create_context();
    setup(
        &mut member3_test_context,
        member3_mint_keypair.insecure_clone(),
        vec![ExtensionInitializationParams::GroupMemberPointer {
            authority: Some(member3_authority.pubkey()),
            member_address: Some(member3_mint_keypair.pubkey()),
        }],
    )
    .await;
    let member3_token_context = member3_test_context.token_context.take().unwrap();

    // // fails without more lamports for new rent-exemption
    // let error = member1_token_context
    //     .token
    //     .token_group_initialize_member(
    //         &member1_token_context.mint_authority.pubkey(),
    //         &group_mint_keypair.pubkey(),
    //         &group_authority.pubkey(),
    //         &[
    //             &member1_token_context.mint_authority,
    //             &group_authority,
    //         ],
    //     )
    //     .await
    //     .unwrap_err();
    // assert_eq!(
    //     error,
    //     TokenClientError::Client(Box::new(TransportError::TransactionError(
    //         TransactionError::InsufficientFundsForRent { account_index: 1 }
    //     )))
    // );

    // fail wrong mint authority signer
    let not_mint_authority = Keypair::new();
    let error = member1_token_context
        .token
        .token_group_initialize_member_with_rent_transfer(
            &payer.pubkey(),
            &not_mint_authority.pubkey(),
            &group_mint_keypair.pubkey(),
            &group_authority.pubkey(),
            &[&payer, &not_mint_authority, &group_authority],
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        TokenClientError::Client(Box::new(TransportError::TransactionError(
            TransactionError::InstructionError(
                1,
                InstructionError::Custom(TokenGroupError::IncorrectMintAuthority as u32)
            )
        )))
    );

    // fail wrong group update authority signer
    let not_group_update_authority = Keypair::new();
    let error = member1_token_context
        .token
        .token_group_initialize_member_with_rent_transfer(
            &payer.pubkey(),
            &member1_token_context.mint_authority.pubkey(),
            &group_mint_keypair.pubkey(),
            &not_group_update_authority.pubkey(),
            &[
                &payer,
                &member1_token_context.mint_authority,
                &not_group_update_authority,
            ],
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        TokenClientError::Client(Box::new(TransportError::TransactionError(
            TransactionError::InstructionError(
                1,
                InstructionError::Custom(TokenGroupError::IncorrectUpdateAuthority as u32)
            )
        )))
    );

    member1_token_context
        .token
        .token_group_initialize_member_with_rent_transfer(
            &payer.pubkey(),
            &member1_token_context.mint_authority.pubkey(),
            &group_mint_keypair.pubkey(),
            &group_authority.pubkey(),
            &[
                &payer,
                &member1_token_context.mint_authority,
                &group_authority,
            ],
        )
        .await
        .unwrap();

    // check that the data is correct
    let mint_info = member1_token_context.token.get_mint_info().await.unwrap();
    let member_bytes = mint_info.get_extension_bytes::<TokenGroupMember>().unwrap();
    let fetched_member = pod_from_bytes::<TokenGroupMember>(member_bytes).unwrap();
    assert_eq!(
        fetched_member,
        &TokenGroupMember {
            mint: member1_mint_keypair.pubkey(),
            group: group_mint_keypair.pubkey(),
            member_number: 1.try_into().unwrap(),
        }
    );

    // fail double-init
    let error = member1_token_context
        .token
        .token_group_initialize_member(
            &member1_token_context.mint_authority.pubkey(),
            &group_mint_keypair.pubkey(),
            &group_authority.pubkey(),
            &[&member1_token_context.mint_authority, &group_authority],
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        TokenClientError::Client(Box::new(TransportError::TransactionError(
            TransactionError::InstructionError(
                0,
                InstructionError::Custom(TokenError::ExtensionAlreadyInitialized as u32)
            )
        )))
    );

    // Now the others
    member2_token_context
        .token
        .token_group_initialize_member_with_rent_transfer(
            &payer.pubkey(),
            &member2_token_context.mint_authority.pubkey(),
            &group_mint_keypair.pubkey(),
            &group_authority.pubkey(),
            &[
                &payer,
                &member2_token_context.mint_authority,
                &group_authority,
            ],
        )
        .await
        .unwrap();
    let mint_info = member2_token_context.token.get_mint_info().await.unwrap();
    let member_bytes = mint_info.get_extension_bytes::<TokenGroupMember>().unwrap();
    let fetched_member = pod_from_bytes::<TokenGroupMember>(member_bytes).unwrap();
    assert_eq!(
        fetched_member,
        &TokenGroupMember {
            mint: member2_mint_keypair.pubkey(),
            group: group_mint_keypair.pubkey(),
            member_number: 2.try_into().unwrap(),
        }
    );

    member3_token_context
        .token
        .token_group_initialize_member_with_rent_transfer(
            &payer.pubkey(),
            &member3_token_context.mint_authority.pubkey(),
            &group_mint_keypair.pubkey(),
            &group_authority.pubkey(),
            &[
                &payer,
                &member3_token_context.mint_authority,
                &group_authority,
            ],
        )
        .await
        .unwrap();
    let mint_info = member3_token_context.token.get_mint_info().await.unwrap();
    let member_bytes = mint_info.get_extension_bytes::<TokenGroupMember>().unwrap();
    let fetched_member = pod_from_bytes::<TokenGroupMember>(member_bytes).unwrap();
    assert_eq!(
        fetched_member,
        &TokenGroupMember {
            mint: member3_mint_keypair.pubkey(),
            group: group_mint_keypair.pubkey(),
            member_number: 3.try_into().unwrap(),
        }
    );
}

#[tokio::test]
async fn fail_without_member_pointer() {
    let payer = Keypair::new();

    let group_authority = Keypair::new();
    let group_mint_keypair = Keypair::new();

    let member_mint_keypair = Keypair::new();

    let program_test = setup_program_test();
    let mut context = program_test.start_with_context().await;
    context.set_account(
        &payer.pubkey(),
        &SolanaAccount {
            lamports: 500_000_000,
            ..SolanaAccount::default()
        }
        .into(),
    );
    let context = Arc::new(tokio::sync::Mutex::new(context));

    let create_context = || TestContext {
        context: context.clone(),
        token_context: None,
    };

    let mut group_test_context = create_context();
    setup(
        &mut group_test_context,
        group_mint_keypair.insecure_clone(),
        vec![ExtensionInitializationParams::GroupPointer {
            authority: Some(group_authority.pubkey()),
            group_address: Some(group_mint_keypair.pubkey()),
        }],
    )
    .await;
    let group_token_context = group_test_context.token_context.take().unwrap();

    let mut member_test_context = create_context();
    member_test_context
        .init_token_with_mint_keypair_and_freeze_authority(member_mint_keypair, vec![], None)
        .await
        .unwrap();
    let member_token_context = member_test_context.token_context.take().unwrap();

    group_token_context
        .token
        .token_group_initialize_with_rent_transfer(
            &payer.pubkey(),
            &group_token_context.mint_authority.pubkey(),
            &group_authority.pubkey(),
            5,
            &[&payer, &group_token_context.mint_authority],
        )
        .await
        .unwrap();

    let error = member_token_context
        .token
        .token_group_initialize_member_with_rent_transfer(
            &payer.pubkey(),
            &member_token_context.mint_authority.pubkey(),
            &group_mint_keypair.pubkey(),
            &group_authority.pubkey(),
            &[
                &payer,
                &member_token_context.mint_authority,
                &group_authority,
            ],
        )
        .await
        .unwrap_err();
    assert_eq!(
        error,
        TokenClientError::Client(Box::new(TransportError::TransactionError(
            TransactionError::InstructionError(
                1,
                InstructionError::Custom(TokenError::InvalidExtensionCombination as u32)
            )
        )))
    );
}

#[tokio::test]
async fn fail_init_in_another_mint() {
    let payer = Keypair::new();

    let group_authority = Keypair::new();
    let group_mint_keypair = Keypair::new();

    let member_authority = Keypair::new();
    let first_member_mint_keypair = Keypair::new();
    let second_member_mint_keypair = Keypair::new();

    let program_test = setup_program_test();
    let mut context = program_test.start_with_context().await;
    context.set_account(
        &payer.pubkey(),
        &SolanaAccount {
            lamports: 500_000_000,
            ..SolanaAccount::default()
        }
        .into(),
    );
    let context = Arc::new(tokio::sync::Mutex::new(context));

    let create_context = || TestContext {
        context: context.clone(),
        token_context: None,
    };

    let mut group_test_context = create_context();
    setup(
        &mut group_test_context,
        group_mint_keypair.insecure_clone(),
        vec![ExtensionInitializationParams::GroupPointer {
            authority: Some(group_authority.pubkey()),
            group_address: Some(group_mint_keypair.pubkey()),
        }],
    )
    .await;
    let group_token_context = group_test_context.token_context.take().unwrap();

    group_token_context
        .token
        .token_group_initialize_with_rent_transfer(
            &payer.pubkey(),
            &group_token_context.mint_authority.pubkey(),
            &group_authority.pubkey(),
            5,
            &[&payer, &group_token_context.mint_authority],
        )
        .await
        .unwrap();

    let mut member_test_context = create_context();
    setup(
        &mut member_test_context,
        second_member_mint_keypair.insecure_clone(),
        vec![ExtensionInitializationParams::GroupMemberPointer {
            authority: Some(member_authority.pubkey()),
            member_address: Some(second_member_mint_keypair.pubkey()),
        }],
    )
    .await;
    let member_token_context = member_test_context.token_context.take().unwrap();

    let error = member_token_context
        .token
        .process_ixs(
            &[spl_token_group_interface::instruction::initialize_member(
                &spl_token_2022::id(),
                &first_member_mint_keypair.pubkey(),
                member_token_context.token.get_address(),
                &member_token_context.mint_authority.pubkey(),
                &group_mint_keypair.pubkey(),
                &group_authority.pubkey(),
            )],
            &[&member_token_context.mint_authority, &group_authority],
        )
        .await
        .unwrap_err();

    assert_eq!(
        error,
        TokenClientError::Client(Box::new(TransportError::TransactionError(
            TransactionError::InstructionError(
                0,
                InstructionError::Custom(TokenError::MintMismatch as u32)
            )
        )))
    );
}

#[tokio::test]
async fn fail_without_signatures() {
    let payer = Keypair::new();

    let group_authority = Keypair::new();
    let group_mint_keypair = Keypair::new();

    let member_authority = Keypair::new();
    let member_mint_keypair = Keypair::new();

    let program_test = setup_program_test();
    let mut context = program_test.start_with_context().await;
    context.set_account(
        &payer.pubkey(),
        &SolanaAccount {
            lamports: 500_000_000,
            ..SolanaAccount::default()
        }
        .into(),
    );
    let context = Arc::new(tokio::sync::Mutex::new(context));

    let create_context = || TestContext {
        context: context.clone(),
        token_context: None,
    };

    let mut group_test_context = create_context();
    setup(
        &mut group_test_context,
        group_mint_keypair.insecure_clone(),
        vec![ExtensionInitializationParams::GroupPointer {
            authority: Some(group_authority.pubkey()),
            group_address: Some(group_mint_keypair.pubkey()),
        }],
    )
    .await;
    let group_token_context = group_test_context.token_context.take().unwrap();

    group_token_context
        .token
        .token_group_initialize_with_rent_transfer(
            &payer.pubkey(),
            &group_token_context.mint_authority.pubkey(),
            &group_authority.pubkey(),
            5,
            &[&payer, &group_token_context.mint_authority],
        )
        .await
        .unwrap();

    let mut member_test_context = create_context();
    setup(
        &mut member_test_context,
        member_mint_keypair.insecure_clone(),
        vec![ExtensionInitializationParams::GroupMemberPointer {
            authority: Some(member_authority.pubkey()),
            member_address: Some(member_mint_keypair.pubkey()),
        }],
    )
    .await;
    let member_token_context = member_test_context.token_context.take().unwrap();

    // Missing mint authority
    let mut instruction = spl_token_group_interface::instruction::initialize_member(
        &spl_token_2022::id(),
        &member_mint_keypair.pubkey(),
        member_token_context.token.get_address(),
        &member_token_context.mint_authority.pubkey(),
        &group_mint_keypair.pubkey(),
        &group_authority.pubkey(),
    );
    instruction.accounts[2].is_signer = false;
    let error = member_token_context
        .token
        .process_ixs(&[instruction], &[&group_authority])
        .await
        .unwrap_err();
    assert_eq!(
        error,
        TokenClientError::Client(Box::new(TransportError::TransactionError(
            TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature)
        )))
    );

    // Missing group update authority
    let mut instruction = spl_token_group_interface::instruction::initialize_member(
        &spl_token_2022::id(),
        &member_mint_keypair.pubkey(),
        member_token_context.token.get_address(),
        &member_token_context.mint_authority.pubkey(),
        &group_mint_keypair.pubkey(),
        &group_authority.pubkey(),
    );
    instruction.accounts[4].is_signer = false;
    let error = member_token_context
        .token
        .process_ixs(&[instruction], &[&member_token_context.mint_authority])
        .await
        .unwrap_err();
    assert_eq!(
        error,
        TokenClientError::Client(Box::new(TransportError::TransactionError(
            TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature)
        )))
    );
}

#[test]
fn builder_test() {
    use crate::GovernorConfigBuilder;

    let builder = GovernorConfigBuilder::default()
        .with_duration(crate::DEFAULT_DURATION)
        .with_size(crate::DEFAULT_QUOTA_SIZE.unwrap());

    assert_eq!(GovernorConfigBuilder::default(), builder);

    let builder1 = builder.clone().with_duration_in_millis(5000);
    let builder2 = builder.with_duration_in_secs(5);

    assert_eq!(builder1, builder2);
}

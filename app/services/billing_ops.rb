# frozen_string_literal: true

# BillingOps
# =============================================================================
# Serviço Rails para um problema real de mercado:
# reconciliação automática de faturas B2B, detecção de cobranças indevidas,
# duplicidades, divergências contratuais, pagamentos parciais, inadimplência,
# disputas, créditos, auditoria e priorização de cobrança.
#
# Sugestão de caminho:
#   app/services/billing_ops.rb
#
# Modelos ActiveRecord esperados:
#   Account
#   Customer
#   Contract
#   ContractItem
#   Invoice
#   InvoiceLine
#   Payment
#   PaymentAllocation
#   CreditNote
#   Dispute
#   BillingAuditEvent
#
# O arquivo demonstra arquitetura de domínio, regras de negócio, idempotência,
# auditoria, score de risco, conciliação e relatórios operacionais.
# =============================================================================

require "set"
require "json"
require "csv"
require "digest"
require "securerandom"
require "bigdecimal"
require "bigdecimal/util"

module BillingOps
  class Error < StandardError; end
  class ValidationError < Error; end
  class ReconciliationError < Error; end
  class DuplicateError < Error; end
  class ContractMismatchError < Error; end
  class AllocationError < Error; end
  class DisputeError < Error; end
  class NotFoundError < Error; end

  Result = Struct.new(:ok?, :value, :errors, :meta, keyword_init: true) do
    def self.success(value = nil, meta: {})
      new(ok?: true, value: value, errors: [], meta: meta)
    end

    def self.failure(*errors, meta: {})
      new(ok?: false, value: nil, errors: errors.flatten.compact, meta: meta)
    end

    def unwrap!
      raise BillingOps::Error, errors.join(", ") unless ok?
      value
    end
  end

  Finding = Struct.new(
    :code,
    :severity,
    :message,
    :amount,
    :metadata,
    keyword_init: true
  )

  ReconciliationSummary = Struct.new(
    :invoice_id,
    :status,
    :gross_amount,
    :expected_amount,
    :paid_amount,
    :open_amount,
    :findings,
    :risk_score,
    keyword_init: true
  )

  module Support
    module_function

    def now
      defined?(Time.zone) && Time.zone ? Time.zone.now : Time.now
    end

    def decimal(value)
      value.is_a?(BigDecimal) ? value : value.to_d
    rescue StandardError
      BigDecimal("0")
    end

    def money(value)
      decimal(value).round(2)
    end

    def normalize_text(value)
      value.to_s.strip.downcase.gsub(/\s+/, " ")
    end

    def normalize_reference(value)
      normalize_text(value).gsub(/[^a-z0-9]/, "")
    end

    def safe_json(value)
      JSON.generate(value)
    rescue JSON::GeneratorError
      JSON.generate(value.to_s)
    end

    def clamp(value, minimum, maximum)
      [[value, minimum].max, maximum].min
    end

    def percentage(numerator, denominator)
      denominator = decimal(denominator)
      return 0.0 if denominator.zero?

      (decimal(numerator) / denominator * 100).to_f
    end

    def days_between(from, to)
      ((to.to_date - from.to_date).to_i rescue 0)
    end

    def sha256(*parts)
      Digest::SHA256.hexdigest(parts.flatten.compact.map(&:to_s).join("|"))
    end
  end

  class Configuration
    DEFAULTS = {
      amount_tolerance: BigDecimal("0.01"),
      percentage_tolerance: 0.5,
      duplicate_window_days: 120,
      late_payment_grace_days: 3,
      critical_overcharge_percentage: 20.0,
      severe_overcharge_percentage: 10.0,
      dispute_auto_open_threshold: 70.0,
      dunning_high_risk_threshold: 65.0,
      minimum_collection_amount: BigDecimal("10.00"),
      default_currency: "BRL",
      aging_buckets: [0, 30, 60, 90, 120],
      max_auto_credit_amount: BigDecimal("500.00"),
      tax_tolerance_percentage: 1.0,
      quantity_tolerance_percentage: 0.0,
      price_tolerance_percentage: 0.5
    }.freeze

    def initialize(overrides = {})
      @values = DEFAULTS.merge(overrides.transform_keys(&:to_sym))
    end

    def [](key)
      @values.fetch(key.to_sym)
    end

    def to_h
      @values.dup
    end
  end

  class Logger
    def initialize(logger: defined?(Rails) ? Rails.logger : nil)
      @logger = logger
    end

    def info(message, payload = {})
      emit(:info, message, payload)
    end

    def warn(message, payload = {})
      emit(:warn, message, payload)
    end

    def error(message, payload = {})
      emit(:error, message, payload)
    end

    private

    def emit(level, message, payload)
      text = "[BillingOps] #{message} #{Support.safe_json(payload)}"

      if @logger&.respond_to?(level)
        @logger.public_send(level, text)
      else
        $stdout.puts(text)
      end
    end
  end

  class AuditTrail
    def initialize(logger: Logger.new)
      @logger = logger
    end

    def record!(action:, actor:, subject:, metadata: {})
      payload = {
        action: action,
        actor_type: actor&.class&.name,
        actor_id: actor&.respond_to?(:id) ? actor.id : nil,
        subject_type: subject&.class&.name,
        subject_id: subject&.respond_to?(:id) ? subject.id : nil,
        metadata: metadata,
        occurred_at: Support.now
      }

      if defined?(BillingAuditEvent) && BillingAuditEvent.respond_to?(:create!)
        BillingAuditEvent.create!(payload)
      else
        @logger.info("audit", payload)
      end

      payload
    end
  end

  class Repository
    def invoice(id)
      Invoice.find(id)
    rescue StandardError
      raise NotFoundError, "invoice #{id} not found"
    end

    def contract_for(invoice)
      return invoice.contract if invoice.respond_to?(:contract) && invoice.contract

      if invoice.respond_to?(:contract_id) && invoice.contract_id
        Contract.find(invoice.contract_id)
      else
        nil
      end
    end

    def invoice_lines(invoice)
      invoice.respond_to?(:invoice_lines) ? invoice.invoice_lines : InvoiceLine.where(invoice_id: invoice.id)
    end

    def contract_items(contract)
      return [] unless contract
      contract.respond_to?(:contract_items) ? contract.contract_items : ContractItem.where(contract_id: contract.id)
    end

    def payments_for(invoice)
      if defined?(PaymentAllocation)
        Payment
          .joins(:payment_allocations)
          .where(payment_allocations: { invoice_id: invoice.id })
      elsif invoice.respond_to?(:payments)
        invoice.payments
      else
        Payment.none
      end
    end

    def allocations_for(invoice)
      return PaymentAllocation.where(invoice_id: invoice.id) if defined?(PaymentAllocation)
      []
    end

    def disputes_for(invoice)
      return invoice.disputes if invoice.respond_to?(:disputes)
      Dispute.where(invoice_id: invoice.id)
    end

    def duplicate_candidates(invoice, days:)
      scope = Invoice.where.not(id: invoice.id)

      if invoice.respond_to?(:customer_id)
        scope = scope.where(customer_id: invoice.customer_id)
      end

      if invoice.respond_to?(:issued_at) && invoice.issued_at
        from = invoice.issued_at - days.days
        to = invoice.issued_at + days.days
        scope = scope.where(issued_at: from..to)
      end

      scope
    end
  end

  class InvoiceSnapshot
    attr_reader :invoice, :repository

    def initialize(invoice, repository: Repository.new)
      @invoice = invoice
      @repository = repository
    end

    def id
      invoice.id
    end

    def number
      invoice.respond_to?(:number) ? invoice.number.to_s : id.to_s
    end

    def currency
      invoice.respond_to?(:currency) && invoice.currency.present? ? invoice.currency : "BRL"
    end

    def issued_at
      invoice.respond_to?(:issued_at) ? invoice.issued_at : nil
    end

    def due_at
      invoice.respond_to?(:due_at) ? invoice.due_at : nil
    end

    def customer_id
      invoice.respond_to?(:customer_id) ? invoice.customer_id : nil
    end

    def contract_id
      invoice.respond_to?(:contract_id) ? invoice.contract_id : nil
    end

    def gross_amount
      if invoice.respond_to?(:gross_amount) && invoice.gross_amount
        Support.money(invoice.gross_amount)
      else
        repository.invoice_lines(invoice).sum { |line| line_total(line) }
      end
    end

    def tax_amount
      invoice.respond_to?(:tax_amount) ? Support.money(invoice.tax_amount) : 0.to_d
    end

    def discount_amount
      invoice.respond_to?(:discount_amount) ? Support.money(invoice.discount_amount) : 0.to_d
    end

    def reference
      value =
        if invoice.respond_to?(:external_reference)
          invoice.external_reference
        elsif invoice.respond_to?(:reference)
          invoice.reference
        end

      Support.normalize_reference(value)
    end

    def line_total(line)
      if line.respond_to?(:total_amount) && line.total_amount
        Support.money(line.total_amount)
      else
        quantity = line.respond_to?(:quantity) ? Support.decimal(line.quantity) : 1.to_d
        unit_price = line.respond_to?(:unit_price) ? Support.decimal(line.unit_price) : 0.to_d
        Support.money(quantity * unit_price)
      end
    end
  end

  class ContractSnapshot
    attr_reader :contract, :repository

    def initialize(contract, repository: Repository.new)
      @contract = contract
      @repository = repository
    end

    def active_on?(date)
      return false unless contract
      starts_on = contract.respond_to?(:starts_on) ? contract.starts_on : nil
      ends_on = contract.respond_to?(:ends_on) ? contract.ends_on : nil

      after_start = starts_on.nil? || date.to_date >= starts_on.to_date
      before_end = ends_on.nil? || date.to_date <= ends_on.to_date
      after_start && before_end
    end

    def currency
      contract.respond_to?(:currency) ? contract.currency.to_s : nil
    end

    def payment_term_days
      contract.respond_to?(:payment_term_days) ? contract.payment_term_days.to_i : nil
    end

    def items
      repository.contract_items(contract)
    end
  end

  class LineMatcher
    Match = Struct.new(
      :invoice_line,
      :contract_item,
      :confidence,
      :reason,
      keyword_init: true
    )

    def initialize(repository: Repository.new)
      @repository = repository
    end

    def call(invoice:, contract:)
      lines = @repository.invoice_lines(invoice).to_a
      items = @repository.contract_items(contract).to_a
      used_item_ids = Set.new

      lines.map do |line|
        best = items
          .reject { |item| used_item_ids.include?(item.id) }
          .map { |item| score(line, item) }
          .max_by(&:confidence)

        if best && best.confidence >= 0.45
          used_item_ids << best.contract_item.id
          best
        else
          Match.new(
            invoice_line: line,
            contract_item: nil,
            confidence: best&.confidence || 0.0,
            reason: "no reliable contract item match"
          )
        end
      end
    end

    private

    def score(line, item)
      points = 0.0
      reasons = []

      line_code = normalized_value(line, :sku, :code, :item_code)
      item_code = normalized_value(item, :sku, :code, :item_code)

      if line_code.present? && item_code.present? && line_code == item_code
        points += 0.65
        reasons << "code"
      end

      line_desc = normalized_value(line, :description, :name)
      item_desc = normalized_value(item, :description, :name)

      if line_desc.present? && item_desc.present?
        if line_desc == item_desc
          points += 0.30
          reasons << "description_exact"
        elsif line_desc.include?(item_desc) || item_desc.include?(line_desc)
          points += 0.18
          reasons << "description_partial"
        end
      end

      Match.new(
        invoice_line: line,
        contract_item: item,
        confidence: [points, 1.0].min,
        reason: reasons.join("+")
      )
    end

    def normalized_value(record, *attributes)
      attribute = attributes.find { |name| record.respond_to?(name) && record.public_send(name).present? }
      return "" unless attribute

      Support.normalize_text(record.public_send(attribute))
    end
  end

  class BaseRule
    attr_reader :repository, :config

    def initialize(repository: Repository.new, config: Configuration.new)
      @repository = repository
      @config = config
    end

    def finding(code:, severity:, message:, amount: 0, metadata: {})
      Finding.new(
        code: code,
        severity: severity,
        message: message,
        amount: Support.money(amount),
        metadata: metadata
      )
    end
  end

  class DuplicateInvoiceRule < BaseRule
    def call(invoice:)
            snapshot = InvoiceSnapshot.new(invoice, repository: repository)
            candidates = repository.duplicate_candidates(
              invoice,
              days: config[:duplicate_window_days]
            )

            duplicates = candidates.select do |candidate|
              other = InvoiceSnapshot.new(candidate, repository: repository)

              same_reference =
                snapshot.reference.present? &&
                other.reference.present? &&
                snapshot.reference == other.reference

              same_number =
                snapshot.number.present? &&
                other.number.present? &&
                snapshot.number == other.number

              same_amount =
                (snapshot.gross_amount - other.gross_amount).abs <= config[:amount_tolerance]

              (same_reference || same_number) && same_amount
            end

            duplicates.map do |candidate|
              finding(
                code: "duplicate_invoice",
                severity: :critical,
                message: "Potential duplicate invoice detected",
                amount: snapshot.gross_amount,
                metadata: { duplicate_invoice_id: candidate.id }
              )
            end
    end
  end

  class ContractPresenceRule < BaseRule
    def call(invoice:)
            contract = repository.contract_for(invoice)
            return [] if contract

            [
              finding(
                code: "missing_contract",
                severity: :high,
                message: "Invoice has no associated contract",
                amount: InvoiceSnapshot.new(invoice, repository: repository).gross_amount
              )
            ]
    end
  end

  class ContractValidityRule < BaseRule
    def call(invoice:)
            contract = repository.contract_for(invoice)
            return [] unless contract

            invoice_snapshot = InvoiceSnapshot.new(invoice, repository: repository)
            contract_snapshot = ContractSnapshot.new(contract, repository: repository)
            date = invoice_snapshot.issued_at || Support.now

            return [] if contract_snapshot.active_on?(date)

            [
              finding(
                code: "contract_outside_validity",
                severity: :high,
                message: "Invoice date is outside contract validity period",
                amount: invoice_snapshot.gross_amount,
                metadata: { invoice_date: date }
              )
            ]
    end
  end

  class CurrencyMismatchRule < BaseRule
    def call(invoice:)
            contract = repository.contract_for(invoice)
            return [] unless contract

            invoice_currency = InvoiceSnapshot.new(invoice, repository: repository).currency
            contract_currency = ContractSnapshot.new(contract, repository: repository).currency

            return [] if contract_currency.blank? || invoice_currency == contract_currency

            [
              finding(
                code: "currency_mismatch",
                severity: :high,
                message: "Invoice currency differs from contract currency",
                metadata: {
                  invoice_currency: invoice_currency,
                  contract_currency: contract_currency
                }
              )
            ]
    end
  end

  class DueDateRule < BaseRule
    def call(invoice:)
            contract = repository.contract_for(invoice)
            return [] unless contract

            invoice_snapshot = InvoiceSnapshot.new(invoice, repository: repository)
            contract_snapshot = ContractSnapshot.new(contract, repository: repository)
            term_days = contract_snapshot.payment_term_days

            return [] unless term_days && invoice_snapshot.issued_at && invoice_snapshot.due_at

            expected = invoice_snapshot.issued_at.to_date + term_days.days
            actual = invoice_snapshot.due_at.to_date
            return [] if expected == actual

            [
              finding(
                code: "payment_term_mismatch",
                severity: :medium,
                message: "Invoice due date differs from contract payment terms",
                metadata: {
                  expected_due_date: expected,
                  actual_due_date: actual,
                  payment_term_days: term_days
                }
              )
            ]
    end
  end

  class LinePriceRule < BaseRule
    def call(invoice:)
            contract = repository.contract_for(invoice)
            return [] unless contract

            matches = LineMatcher.new(repository: repository).call(
              invoice: invoice,
              contract: contract
            )

            matches.filter_map do |match|
              next unless match.contract_item

              line = match.invoice_line
              item = match.contract_item

              line_price = line.respond_to?(:unit_price) ? Support.decimal(line.unit_price) : nil
              contract_price = item.respond_to?(:unit_price) ? Support.decimal(item.unit_price) : nil
              next unless line_price && contract_price && !contract_price.zero?

              delta = line_price - contract_price
              percentage = Support.percentage(delta.abs, contract_price)
              next if percentage <= config[:price_tolerance_percentage]

              severity =
                if percentage >= config[:critical_overcharge_percentage]
                  :critical
                elsif percentage >= config[:severe_overcharge_percentage]
                  :high
                else
                  :medium
                end

              finding(
                code: "unit_price_mismatch",
                severity: severity,
                message: "Invoice unit price differs from contracted price",
                amount: delta,
                metadata: {
                  invoice_line_id: line.id,
                  contract_item_id: item.id,
                  invoice_unit_price: line_price.to_f,
                  contract_unit_price: contract_price.to_f,
                  difference_percentage: percentage.round(2),
                  confidence: match.confidence
                }
              )
            end
    end
  end

  class LineQuantityRule < BaseRule
    def call(invoice:)
            contract = repository.contract_for(invoice)
            return [] unless contract

            matches = LineMatcher.new(repository: repository).call(
              invoice: invoice,
              contract: contract
            )

            matches.filter_map do |match|
              next unless match.contract_item

              line = match.invoice_line
              item = match.contract_item
              next unless line.respond_to?(:quantity) && item.respond_to?(:quantity)

              invoice_qty = Support.decimal(line.quantity)
              contract_qty = Support.decimal(item.quantity)
              next if contract_qty.zero?

              percentage = Support.percentage((invoice_qty - contract_qty).abs, contract_qty)
              next if percentage <= config[:quantity_tolerance_percentage]

              finding(
                code: "quantity_mismatch",
                severity: :medium,
                message: "Invoice quantity differs from contract quantity",
                metadata: {
                  invoice_line_id: line.id,
                  contract_item_id: item.id,
                  invoice_quantity: invoice_qty.to_f,
                  contract_quantity: contract_qty.to_f,
                  difference_percentage: percentage.round(2)
                }
              )
            end
    end
  end

  class UnknownLineRule < BaseRule
    def call(invoice:)
            contract = repository.contract_for(invoice)
            return [] unless contract

            LineMatcher.new(repository: repository)
              .call(invoice: invoice, contract: contract)
              .filter_map do |match|
                next if match.contract_item

                line = match.invoice_line
                amount = InvoiceSnapshot.new(invoice, repository: repository).line_total(line)

                finding(
                  code: "unmatched_invoice_line",
                  severity: :high,
                  message: "Invoice contains a line not found in the contract",
                  amount: amount,
                  metadata: {
                    invoice_line_id: line.id,
                    confidence: match.confidence
                  }
                )
              end
    end
  end

  class TaxConsistencyRule < BaseRule
    def call(invoice:)
            snapshot = InvoiceSnapshot.new(invoice, repository: repository)
            return [] unless invoice.respond_to?(:tax_percentage) && invoice.tax_percentage

            base = snapshot.gross_amount - snapshot.tax_amount
            expected_tax = Support.money(base * Support.decimal(invoice.tax_percentage) / 100)
            difference = (snapshot.tax_amount - expected_tax).abs

            return [] if base.zero?
            percentage = Support.percentage(difference, expected_tax.nonzero? || 1)
            return [] if percentage <= config[:tax_tolerance_percentage]

            [
              finding(
                code: "tax_mismatch",
                severity: :medium,
                message: "Invoice tax amount is inconsistent with tax rate",
                amount: difference,
                metadata: {
                  expected_tax: expected_tax.to_f,
                  actual_tax: snapshot.tax_amount.to_f,
                  difference_percentage: percentage.round(2)
                }
              )
            ]
    end
  end

  class NegativeLineRule < BaseRule
    def call(invoice:)
            repository.invoice_lines(invoice).filter_map do |line|
              total = InvoiceSnapshot.new(invoice, repository: repository).line_total(line)
              next unless total.negative?

              finding(
                code: "negative_invoice_line",
                severity: :low,
                message: "Invoice contains a negative line",
                amount: total.abs,
                metadata: { invoice_line_id: line.id }
              )
            end
    end
  end

  class ZeroValueLineRule < BaseRule
    def call(invoice:)
            repository.invoice_lines(invoice).filter_map do |line|
              total = InvoiceSnapshot.new(invoice, repository: repository).line_total(line)
              next unless total.zero?

              finding(
                code: "zero_value_line",
                severity: :low,
                message: "Invoice contains a zero-value line",
                metadata: { invoice_line_id: line.id }
              )
            end
    end
  end

  class LateInvoiceRule < BaseRule
    def call(invoice:)
            snapshot = InvoiceSnapshot.new(invoice, repository: repository)
            return [] unless snapshot.issued_at && snapshot.due_at

            term = Support.days_between(snapshot.issued_at, snapshot.due_at)
            return [] if term >= 0

            [
              finding(
                code: "invalid_due_date",
                severity: :high,
                message: "Due date is earlier than invoice issue date",
                metadata: { term_days: term }
              )
            ]
    end
  end

  class ExcessiveDiscountRule < BaseRule
    def call(invoice:)
            snapshot = InvoiceSnapshot.new(invoice, repository: repository)
            return [] if snapshot.gross_amount.zero?

            percentage = Support.percentage(snapshot.discount_amount, snapshot.gross_amount)
            return [] if percentage <= 50.0

            [
              finding(
                code: "excessive_discount",
                severity: :medium,
                message: "Invoice discount exceeds 50% of gross amount",
                amount: snapshot.discount_amount,
                metadata: { discount_percentage: percentage.round(2) }
              )
            ]
    end
  end

  class ReferencePresenceRule < BaseRule
    def call(invoice:)
            snapshot = InvoiceSnapshot.new(invoice, repository: repository)
            return [] if snapshot.reference.present?

            [
              finding(
                code: "missing_reference",
                severity: :low,
                message: "Invoice has no external reference"
              )
            ]
    end
  end

  class CurrencyPresenceRule < BaseRule
    def call(invoice:)
            snapshot = InvoiceSnapshot.new(invoice, repository: repository)
            return [] if snapshot.currency.present?

            [
              finding(
                code: "missing_currency",
                severity: :medium,
                message: "Invoice currency is missing"
              )
            ]
    end
  end

  class RuleRegistry
    RULES = [
      DuplicateInvoiceRule,
      ContractPresenceRule,
      ContractValidityRule,
      CurrencyMismatchRule,
      DueDateRule,
      LinePriceRule,
      LineQuantityRule,
      UnknownLineRule,
      TaxConsistencyRule,
      NegativeLineRule,
      ZeroValueLineRule,
      LateInvoiceRule,
      ExcessiveDiscountRule,
      ReferencePresenceRule,
      CurrencyPresenceRule
    ].freeze

    def initialize(repository: Repository.new, config: Configuration.new)
      @repository = repository
      @config = config
    end

    def rules
      @rules ||= RULES.map do |klass|
        klass.new(repository: @repository, config: @config)
      end
    end
  end

  class RiskScorer
    WEIGHTS = {
      low: 5,
      medium: 15,
      high: 30,
      critical: 50
    }.freeze

    def call(findings)
      raw = findings.sum { |finding| WEIGHTS.fetch(finding.severity.to_sym, 0) }

      amount_factor = findings.sum do |finding|
        [finding.amount.to_f.abs / 1000.0, 20.0].min
      end

      Support.clamp(raw + amount_factor, 0.0, 100.0).round(2)
    end
  end

  class PaymentSummary
    def initialize(repository: Repository.new)
      @repository = repository
    end

    def call(invoice:)
      allocations = @repository.allocations_for(invoice)

      paid_amount =
        if allocations.respond_to?(:sum)
          allocations.sum(:amount)
        else
          Array(allocations).sum { |allocation| allocation.respond_to?(:amount) ? allocation.amount : 0 }
        end

      invoice_amount = InvoiceSnapshot.new(invoice, repository: @repository).gross_amount
      open_amount = [invoice_amount - Support.money(paid_amount), 0.to_d].max

      {
        invoice_amount: invoice_amount,
        paid_amount: Support.money(paid_amount),
        open_amount: Support.money(open_amount),
        paid_percentage: Support.percentage(paid_amount, invoice_amount).round(2)
      }
    end
  end

  class Reconciler
    def initialize(
      repository: Repository.new,
      config: Configuration.new,
      registry: nil,
      risk_scorer: RiskScorer.new,
      payment_summary: nil
    )
      @repository = repository
      @config = config
      @registry = registry || RuleRegistry.new(repository: repository, config: config)
      @risk_scorer = risk_scorer
      @payment_summary = payment_summary || PaymentSummary.new(repository: repository)
    end

    def call(invoice:)
      findings = @registry.rules.flat_map do |rule|
        rule.call(invoice: invoice)
      rescue StandardError => error
        [
          Finding.new(
            code: "rule_error",
            severity: :high,
            message: "#{rule.class.name}: #{error.class}: #{error.message}",
            amount: 0.to_d,
            metadata: {}
          )
        ]
      end

      payments = @payment_summary.call(invoice: invoice)
      snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
      expected_amount = expected_amount(invoice)
      risk_score = @risk_scorer.call(findings)

      status =
        if findings.any? { |finding| finding.severity.to_sym == :critical }
          :blocked
        elsif findings.any? { |finding| finding.severity.to_sym == :high }
          :review
        elsif payments[:open_amount].zero?
          :paid
        elsif payments[:paid_amount].positive?
          :partially_paid
        else
          :open
        end

      ReconciliationSummary.new(
        invoice_id: invoice.id,
        status: status,
        gross_amount: snapshot.gross_amount,
        expected_amount: expected_amount,
        paid_amount: payments[:paid_amount],
        open_amount: payments[:open_amount],
        findings: findings,
        risk_score: risk_score
      )
    end

    private

    def expected_amount(invoice)
      contract = @repository.contract_for(invoice)
      return InvoiceSnapshot.new(invoice, repository: @repository).gross_amount unless contract

      @repository.contract_items(contract).sum do |item|
        quantity = item.respond_to?(:quantity) ? Support.decimal(item.quantity) : 1.to_d
        price = item.respond_to?(:unit_price) ? Support.decimal(item.unit_price) : 0.to_d
        Support.money(quantity * price)
      end
    end
  end

  class DuplicateDetector
    def initialize(repository: Repository.new, config: Configuration.new)
      @repository = repository
      @config = config
    end

    def call(invoice:)
      snapshot = InvoiceSnapshot.new(invoice, repository: @repository)

      @repository
        .duplicate_candidates(invoice, days: @config[:duplicate_window_days])
        .map do |candidate|
          other = InvoiceSnapshot.new(candidate, repository: @repository)
          score = 0.0
          reasons = []

          if snapshot.number == other.number
            score += 0.45
            reasons << "same_number"
          end

          if snapshot.reference.present? && snapshot.reference == other.reference
            score += 0.35
            reasons << "same_reference"
          end

          if (snapshot.gross_amount - other.gross_amount).abs <= @config[:amount_tolerance]
            score += 0.20
            reasons << "same_amount"
          end

          {
            invoice_id: candidate.id,
            confidence: [score, 1.0].min.round(2),
            reasons: reasons
          }
        end
        .select { |row| row[:confidence] >= 0.65 }
        .sort_by { |row| -row[:confidence] }
    end
  end

  class PaymentAllocator
    def initialize(repository: Repository.new, audit: AuditTrail.new)
      @repository = repository
      @audit = audit
    end

    def call(payment:, invoices:, actor:)
      available = Support.money(payment.amount)
      allocations = []

      ordered = invoices.sort_by do |invoice|
        [
          invoice.respond_to?(:due_at) && invoice.due_at ? invoice.due_at : Time.at(0),
          invoice.id
        ]
      end

      ActiveRecord::Base.transaction do
        ordered.each do |invoice|
          break if available <= 0

          summary = PaymentSummary.new(repository: @repository).call(invoice: invoice)
          open_amount = summary[:open_amount]
          next if open_amount <= 0

          amount = [available, open_amount].min

          allocation = PaymentAllocation.create!(
            payment_id: payment.id,
            invoice_id: invoice.id,
            amount: amount
          )

          allocations << allocation
          available -= amount

          @audit.record!(
            action: "payment.allocated",
            actor: actor,
            subject: allocation,
            metadata: {
              invoice_id: invoice.id,
              payment_id: payment.id,
              amount: amount.to_f
            }
          )
        end
      end

      Result.success(
        allocations,
        meta: {
          original_payment_amount: Support.money(payment.amount),
          allocated_amount: Support.money(Support.money(payment.amount) - available),
          remaining_amount: Support.money(available)
        }
      )
    end
  end

  class DisputeService
    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      audit: AuditTrail.new,
      config: Configuration.new
    )
      @repository = repository
      @reconciler = reconciler
      @audit = audit
      @config = config
    end

    def auto_open(invoice:, actor: nil)
      summary = @reconciler.call(invoice: invoice)

      return Result.success(nil, meta: { opened: false }) if summary.risk_score < @config[:dispute_auto_open_threshold]

      existing = @repository
        .disputes_for(invoice)
        .where(status: %w[open investigating])
        .first

      return Result.success(existing, meta: { opened: false, existing: true }) if existing

      dispute = Dispute.create!(
        invoice_id: invoice.id,
        status: "open",
        opened_at: Support.now,
        reason: summary.findings.map(&:code).uniq.join(", "),
        disputed_amount: summary.findings.sum(&:amount).abs
      )

      @audit.record!(
        action: "dispute.auto_opened",
        actor: actor,
        subject: dispute,
        metadata: {
          invoice_id: invoice.id,
          risk_score: summary.risk_score,
          finding_codes: summary.findings.map(&:code)
        }
      )

      Result.success(dispute, meta: { opened: true })
    end
  end

  class CreditNoteService
    def initialize(
      repository: Repository.new,
      audit: AuditTrail.new,
      config: Configuration.new
    )
      @repository = repository
      @audit = audit
      @config = config
    end

    def call(invoice:, amount:, reason:, actor:)
      amount = Support.money(amount)
      raise ValidationError, "credit amount must be positive" unless amount.positive?
      raise ValidationError, "reason is required" if reason.to_s.strip.empty?

      summary = PaymentSummary.new(repository: @repository).call(invoice: invoice)
      raise ValidationError, "credit exceeds open amount" if amount > summary[:open_amount]

      automatic = amount <= @config[:max_auto_credit_amount]

      credit = CreditNote.create!(
        invoice_id: invoice.id,
        amount: amount,
        reason: reason,
        status: automatic ? "approved" : "pending_approval",
        approved_at: automatic ? Support.now : nil
      )

      @audit.record!(
        action: "credit_note.created",
        actor: actor,
        subject: credit,
        metadata: {
          invoice_id: invoice.id,
          amount: amount.to_f,
          automatic: automatic
        }
      )

      Result.success(credit, meta: { automatic: automatic })
    end
  end

  class AgingCalculator
    def initialize(config: Configuration.new, repository: Repository.new)
      @config = config
      @repository = repository
    end

    def call(invoice:, reference_date: Support.now.to_date)
      snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
      payment = PaymentSummary.new(repository: @repository).call(invoice: invoice)

      return { bucket: "paid", days_overdue: 0, open_amount: 0.to_d } if payment[:open_amount].zero?
      return { bucket: "not_due", days_overdue: 0, open_amount: payment[:open_amount] } unless snapshot.due_at

      days_overdue = [Support.days_between(snapshot.due_at, reference_date), 0].max
      bucket = bucket_for(days_overdue)

      {
        bucket: bucket,
        days_overdue: days_overdue,
        open_amount: payment[:open_amount]
      }
    end

    private

    def bucket_for(days)
      buckets = @config[:aging_buckets]

      case days
      when 0
        "current"
      when 1..buckets[1]
        "1-#{buckets[1]}"
      when (buckets[1] + 1)..buckets[2]
        "#{buckets[1] + 1}-#{buckets[2]}"
      when (buckets[2] + 1)..buckets[3]
        "#{buckets[2] + 1}-#{buckets[3]}"
      when (buckets[3] + 1)..buckets[4]
        "#{buckets[3] + 1}-#{buckets[4]}"
      else
        "#{buckets[4] + 1}+"
      end
    end
  end

  class CollectionRiskScorer
    def initialize(
      repository: Repository.new,
      aging: AgingCalculator.new,
      reconciler: Reconciler.new
    )
      @repository = repository
      @aging = aging
      @reconciler = reconciler
    end

    def call(invoice:)
      aging_data = @aging.call(invoice: invoice)
      reconciliation = @reconciler.call(invoice: invoice)

      overdue_points =
        case aging_data[:days_overdue]
        when 0 then 0
        when 1..30 then 10
        when 31..60 then 25
        when 61..90 then 40
        when 91..120 then 60
        else 75
        end

      dispute_penalty =
        if reconciliation.status == :blocked
          -20
        elsif reconciliation.status == :review
          -10
        else
          0
        end

      amount_points = [aging_data[:open_amount].to_f / 1000.0, 20].min
      score = Support.clamp(overdue_points + amount_points + dispute_penalty, 0, 100)

      {
        invoice_id: invoice.id,
        score: score.round(2),
        days_overdue: aging_data[:days_overdue],
        open_amount: aging_data[:open_amount],
        reconciliation_status: reconciliation.status
      }
    end
  end

  class DunningPlanner
    def initialize(
      risk_scorer: CollectionRiskScorer.new,
      config: Configuration.new
    )
      @risk_scorer = risk_scorer
      @config = config
    end

    def call(invoice:)
      risk = @risk_scorer.call(invoice: invoice)
      amount = risk[:open_amount]

      return Result.success(action: "none", reason: "below_minimum_amount") if amount < @config[:minimum_collection_amount]

      action =
        if risk[:score] >= 80
          "human_escalation"
        elsif risk[:score] >= @config[:dunning_high_risk_threshold]
          "urgent_contact"
        elsif risk[:days_overdue] > 30
          "second_notice"
        elsif risk[:days_overdue].positive?
          "first_notice"
        else
          "none"
        end

      Result.success(
        {
          invoice_id: invoice.id,
          action: action,
          risk_score: risk[:score],
          days_overdue: risk[:days_overdue],
          open_amount: amount
        }
      )
    end
  end

  class AccountExposure
    def initialize(repository: Repository.new)
      @repository = repository
    end

    def call(customer_id:)
      invoices = Invoice.where(customer_id: customer_id)
      rows = invoices.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        payment = PaymentSummary.new(repository: @repository).call(invoice: invoice)

        {
          invoice_id: invoice.id,
          gross_amount: snapshot.gross_amount,
          open_amount: payment[:open_amount],
          due_at: snapshot.due_at
        }
      end

      {
        customer_id: customer_id,
        invoice_count: rows.length,
        gross_exposure: rows.sum { |row| row[:gross_amount] },
        open_exposure: rows.sum { |row| row[:open_amount] },
        overdue_exposure: rows
          .select { |row| row[:due_at] && row[:due_at].to_date < Support.now.to_date }
          .sum { |row| row[:open_amount] }
      }
    end
  end

  class ReconciliationBatch
    def initialize(
      reconciler: Reconciler.new,
      logger: Logger.new
    )
      @reconciler = reconciler
      @logger = logger
    end

    def call(scope: Invoice.all)
      processed = 0
      blocked = 0
      review = 0
      clean = 0
      failures = []

      scope.find_each do |invoice|
        begin
          summary = @reconciler.call(invoice: invoice)
          processed += 1

          case summary.status
          when :blocked then blocked += 1
          when :review then review += 1
          else clean += 1
          end
        rescue StandardError => error
          failures << {
            invoice_id: invoice.id,
            error: "#{error.class}: #{error.message}"
          }
          @logger.error("batch_reconciliation_failed", invoice_id: invoice.id, error: error.message)
        end
      end

      Result.success(
        {
          processed: processed,
          blocked: blocked,
          review: review,
          clean: clean,
          failures: failures
        }
      )
    end
  end

  class BillingDashboard
    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
    end

    def call(scope: Invoice.all)
      rows = scope.map do |invoice|
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue]
        }
      end

      {
        total_invoices: rows.length,
        gross_amount: rows.sum { |row| row[:gross_amount] },
        paid_amount: rows.sum { |row| row[:paid_amount] },
        open_amount: rows.sum { |row| row[:open_amount] },
        blocked_count: rows.count { |row| row[:status] == :blocked },
        review_count: rows.count { |row| row[:status] == :review },
        overdue_count: rows.count { |row| row[:days_overdue].positive? },
        average_risk_score: rows.empty? ? 0.0 : (
          rows.sum { |row| row[:risk_score] }.to_f / rows.length
        ).round(2),
        rows: rows
      }
    end
  end

  class CsvExporter
    HEADERS = %w[
      invoice_id
      invoice_number
      customer_id
      gross_amount
      paid_amount
      open_amount
      reconciliation_status
      risk_score
      issued_at
      due_at
    ].freeze

    def initialize(repository: Repository.new, reconciler: Reconciler.new)
      @repository = repository
      @reconciler = reconciler
    end

    def call(scope: Invoice.all)
      CSV.generate(headers: true) do |csv|
        csv << HEADERS

        scope.find_each do |invoice|
          snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
          summary = @reconciler.call(invoice: invoice)

          csv << [
            invoice.id,
            snapshot.number,
            snapshot.customer_id,
            summary.gross_amount,
            summary.paid_amount,
            summary.open_amount,
            summary.status,
            summary.risk_score,
            snapshot.issued_at&.iso8601,
            snapshot.due_at&.iso8601
          ]
        end
      end
    end
  end

  class Engine
    attr_reader :repository,
                :config,
                :reconciler,
                :duplicate_detector,
                :aging_calculator,
                :collection_risk_scorer,
                :dunning_planner

    def initialize(repository: Repository.new, config: Configuration.new)
      @repository = repository
      @config = config
      @reconciler = Reconciler.new(repository: repository, config: config)
      @duplicate_detector = DuplicateDetector.new(repository: repository, config: config)
      @aging_calculator = AgingCalculator.new(config: config, repository: repository)
      @collection_risk_scorer = CollectionRiskScorer.new(
        repository: repository,
        aging: aging_calculator,
        reconciler: reconciler
      )
      @dunning_planner = DunningPlanner.new(
        risk_scorer: collection_risk_scorer,
        config: config
      )
    end

    def reconcile(invoice_id:)
      reconciler.call(invoice: repository.invoice(invoice_id))
    end

    def duplicates(invoice_id:)
      duplicate_detector.call(invoice: repository.invoice(invoice_id))
    end

    def aging(invoice_id:)
      aging_calculator.call(invoice: repository.invoice(invoice_id))
    end

    def collection_plan(invoice_id:)
      dunning_planner.call(invoice: repository.invoice(invoice_id))
    end
  end
end

module BillingOps
  # Relatório de divergências financeiras e exposição em contas a receber.
  class ReceivablesRiskReport01
    LOOKBACK_DAYS = 15
    HIGH_VALUE_THRESHOLD = BigDecimal("2500")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Visão de risco de faturamento para apoiar cobrança e atendimento financeiro.
  class ReceivablesRiskReport02
    LOOKBACK_DAYS = 30
    HIGH_VALUE_THRESHOLD = BigDecimal("5000")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Resumo de faturas de alto valor com alertas de conciliação e inadimplência.
  class ReceivablesRiskReport03
    LOOKBACK_DAYS = 45
    HIGH_VALUE_THRESHOLD = BigDecimal("10000")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Análise operacional de contas a receber para fechamento financeiro.
  class ReceivablesRiskReport04
    LOOKBACK_DAYS = 60
    HIGH_VALUE_THRESHOLD = BigDecimal("25000")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Painel de risco por cliente para priorização de contato e disputa.
  class ReceivablesRiskReport05
    LOOKBACK_DAYS = 90
    HIGH_VALUE_THRESHOLD = BigDecimal("1000")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Monitor de qualidade de faturamento com foco em inconsistências contratuais.
  class ReceivablesRiskReport06
    LOOKBACK_DAYS = 120
    HIGH_VALUE_THRESHOLD = BigDecimal("2500")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Relatório de exposição financeira e envelhecimento da carteira.
  class ReceivablesRiskReport07
    LOOKBACK_DAYS = 7
    HIGH_VALUE_THRESHOLD = BigDecimal("5000")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Visão consolidada de reconciliação para equipes de billing operations.
  class ReceivablesRiskReport08
    LOOKBACK_DAYS = 15
    HIGH_VALUE_THRESHOLD = BigDecimal("10000")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Relatório de cobrança com foco em faturas críticas e abertas.
  class ReceivablesRiskReport09
    LOOKBACK_DAYS = 30
    HIGH_VALUE_THRESHOLD = BigDecimal("25000")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Resumo executivo da saúde do faturamento B2B por cliente.
  class ReceivablesRiskReport10
    LOOKBACK_DAYS = 45
    HIGH_VALUE_THRESHOLD = BigDecimal("1000")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Relatório de divergências financeiras e exposição em contas a receber.
  class ReceivablesRiskReport11
    LOOKBACK_DAYS = 60
    HIGH_VALUE_THRESHOLD = BigDecimal("2500")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end

module BillingOps
  # Visão de risco de faturamento para apoiar cobrança e atendimento financeiro.
  class ReceivablesRiskReport12
    LOOKBACK_DAYS = 90
    HIGH_VALUE_THRESHOLD = BigDecimal("5000")

    def initialize(
      repository: Repository.new,
      reconciler: Reconciler.new,
      aging: AgingCalculator.new,
      risk_scorer: CollectionRiskScorer.new
    )
      @repository = repository
      @reconciler = reconciler
      @aging = aging
      @risk_scorer = risk_scorer
    end

    def call(reference_date: Support.now.to_date)
      from = reference_date - LOOKBACK_DAYS.days
      scope = Invoice.all

      if Invoice.respond_to?(:column_names) && Invoice.column_names.include?("issued_at")
        scope = scope.where(issued_at: from.beginning_of_day..reference_date.end_of_day)
      end

      rows = scope.map do |invoice|
        snapshot = InvoiceSnapshot.new(invoice, repository: @repository)
        reconciliation = @reconciler.call(invoice: invoice)
        aging_data = @aging.call(invoice: invoice)
        collection = @risk_scorer.call(invoice: invoice)

        {
          invoice_id: invoice.id,
          customer_id: snapshot.customer_id,
          invoice_number: snapshot.number,
          gross_amount: reconciliation.gross_amount,
          paid_amount: reconciliation.paid_amount,
          open_amount: reconciliation.open_amount,
          status: reconciliation.status,
          risk_score: reconciliation.risk_score,
          collection_risk_score: collection[:score],
          aging_bucket: aging_data[:bucket],
          days_overdue: aging_data[:days_overdue],
          high_value: reconciliation.gross_amount >= HIGH_VALUE_THRESHOLD,
          finding_count: reconciliation.findings.length,
          critical_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :critical
          end,
          high_findings: reconciliation.findings.count do |finding|
            finding.severity.to_sym == :high
          end
        }
      end

      by_customer = rows.group_by { |row| row[:customer_id] }.map do |customer_id, customer_rows|
        {
          customer_id: customer_id,
          invoice_count: customer_rows.length,
          gross_amount: customer_rows.sum { |row| row[:gross_amount] },
          open_amount: customer_rows.sum { |row| row[:open_amount] },
          overdue_open_amount: customer_rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          average_reconciliation_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:risk_score] }.to_f / customer_rows.length
          ).round(2),
          average_collection_risk: customer_rows.empty? ? 0.0 : (
            customer_rows.sum { |row| row[:collection_risk_score] }.to_f / customer_rows.length
          ).round(2),
          blocked_invoices: customer_rows.count { |row| row[:status] == :blocked },
          review_invoices: customer_rows.count { |row| row[:status] == :review }
        }
      end

      Result.success(
        {
          report: self.class.name,
          generated_at: Support.now,
          reference_date: reference_date,
          lookback_days: LOOKBACK_DAYS,
          invoice_count: rows.length,
          gross_amount: rows.sum { |row| row[:gross_amount] },
          paid_amount: rows.sum { |row| row[:paid_amount] },
          open_amount: rows.sum { |row| row[:open_amount] },
          overdue_open_amount: rows
            .select { |row| row[:days_overdue].positive? }
            .sum { |row| row[:open_amount] },
          high_value_invoice_count: rows.count { |row| row[:high_value] },
          blocked_invoice_count: rows.count { |row| row[:status] == :blocked },
          review_invoice_count: rows.count { |row| row[:status] == :review },
          customers: by_customer.sort_by { |row| -row[:open_amount].to_f },
          invoices: rows.sort_by do |row|
            [-row[:risk_score].to_f, -row[:open_amount].to_f]
          end
        }
      )
    rescue StandardError => error
      Result.failure(
        "#{error.class}: #{error.message}",
        meta: {
          report: self.class.name,
          generated_at: Support.now
        }
      )
    end
  end
end
